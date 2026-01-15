"""
Pro-level username search module for InfinityTrace project.

This module performs comprehensive searches for a given username across multiple
platforms and public sources to find publicly available profiles, links, and metadata.
The retrieved data is returned in a structured format with detailed attributes.

Features:
- Asynchronous username search across multiple platforms for faster results
- Rate limiting to respect platform policies
- Structured JSON-compatible output
- Comprehensive platform coverage (13+ platforms)
- Production-ready error handling and logging

Author: Cyber Infinity
Project: InfinityTrace
"""

import re
import time
import logging
import asyncio
import sys
import os
from typing import List, Dict, Optional, Tuple
from datetime import datetime
from urllib.parse import quote_plus

# Add parent directory to path for imports when running as script
if __name__ == "__main__":
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.normalizer import normalize_username
from utils.validators import validate_username

# Try to import aiohttp for async support, fallback to requests
try:
    import aiohttp
    ASYNC_AVAILABLE = True
except ImportError:
    ASYNC_AVAILABLE = False
    logging.warning("aiohttp not available. Install it for async support: pip install aiohttp")

# Import requests for fallback
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Import BeautifulSoup for HTML parsing
try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False
    logging.warning("BeautifulSoup not available. Some features will be limited.")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple rate limiter to respect API and scraping limits - supports both sync and async."""
    
    def __init__(self, requests_per_second: float = 1.0):
        """
        Initialize rate limiter.
        
        Args:
            requests_per_second: Maximum number of requests per second
        """
        self.min_interval = 1.0 / requests_per_second
        self.last_request_time = 0.0
        self._lock = asyncio.Lock() if ASYNC_AVAILABLE else None
    
    def wait(self):
        """Wait if necessary to respect rate limit (synchronous)."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        if time_since_last < self.min_interval:
            time.sleep(self.min_interval - time_since_last)
        self.last_request_time = time.time()
    
    async def wait_async(self):
        """Wait if necessary to respect rate limit (asynchronous)."""
        if self._lock:
            async with self._lock:
                current_time = time.time()
                time_since_last = current_time - self.last_request_time
                if time_since_last < self.min_interval:
                    await asyncio.sleep(self.min_interval - time_since_last)
                self.last_request_time = time.time()
        else:
            # Fallback to synchronous wait
            self.wait()


class PlatformSearcher:
    """Base class for platform-specific searches with both sync and async support."""
    
    def __init__(self, username: str):
        """
        Initialize platform searcher.
        
        Args:
            username: The username to search for
        """
        self.username = username
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                         '(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    def search(self) -> Optional[Dict]:
        """
        Search for username on platform (synchronous).
        
        Returns:
            Dictionary with platform data or None if not found
        """
        raise NotImplementedError("Subclasses must implement search()")
    
    async def search_async(self) -> Optional[Dict]:
        """
        Search for username on platform (asynchronous).
        
        Returns:
            Dictionary with platform data or None if not found
        """
        # Default implementation: run synchronous version in executor
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.search)
    
    def _make_request(self, url: str, method: str = 'HEAD', timeout: int = 10) -> Optional[requests.Response]:
        """
        Make HTTP request with error handling (synchronous).
        
        Args:
            url: URL to request
            method: HTTP method (HEAD, GET)
            timeout: Request timeout in seconds
            
        Returns:
            Response object or None on error
        """
        if not REQUESTS_AVAILABLE:
            logger.warning("requests library not available")
            return None
            
        try:
            if method == 'HEAD':
                response = requests.head(url, headers=self.headers, timeout=timeout, 
                                        allow_redirects=True)
            else:
                response = requests.get(url, headers=self.headers, timeout=timeout,
                                       allow_redirects=True)
            return response
        except requests.RequestException as e:
            logger.debug(f"Request failed for {url}: {str(e)}")
            return None
    
    async def _make_request_async(self, url: str, method: str = 'HEAD', timeout: int = 10) -> Optional[Tuple[int, str]]:
        """
        Make HTTP request with error handling (asynchronous).
        
        Args:
            url: URL to request
            method: HTTP method (HEAD, GET)
            timeout: Request timeout in seconds
            
        Returns:
            Tuple of (status_code, text) or None on error
        """
        if not ASYNC_AVAILABLE:
            # Fallback to synchronous version
            response = self._make_request(url, method, timeout)
            if response:
                return (response.status_code, response.text)
            return None
        
        try:
            timeout_obj = aiohttp.ClientTimeout(total=timeout)
            async with aiohttp.ClientSession(timeout=timeout_obj) as session:
                if method == 'HEAD':
                    async with session.head(url, headers=self.headers, allow_redirects=True) as response:
                        return (response.status, "")
                else:
                    async with session.get(url, headers=self.headers, allow_redirects=True) as response:
                        text = await response.text()
                        return (response.status, text)
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            logger.debug(f"Async request failed for {url}: {str(e)}")
            return None


class InstagramSearcher(PlatformSearcher):
    """Search Instagram for username."""
    
    def search(self) -> Optional[Dict]:
        """Search Instagram for the username."""
        url = f"https://www.instagram.com/{self.username}/"
        response = self._make_request(url, method='HEAD')
        
        if response and response.status_code == 200:
            return {
                "platform": "Instagram",
                "url": url,
                "account_age": "Unknown",
                "profile_image": "Unknown (requires authentication)",
                "bio": "Public profile (details require authentication)",
                "confidence_score": 85
            }
        return None
    
    async def search_async(self) -> Optional[Dict]:
        """Search Instagram for the username (async)."""
        url = f"https://www.instagram.com/{self.username}/"
        result = await self._make_request_async(url, method='HEAD')
        
        if result and result[0] == 200:
            return {
                "platform": "Instagram",
                "url": url,
                "account_age": "Unknown",
                "profile_image": "Unknown (requires authentication)",
                "bio": "Public profile (details require authentication)",
                "confidence_score": 85
            }
        return None


class GitHubSearcher(PlatformSearcher):
    """Search GitHub for username."""
    
    def search(self) -> Optional[Dict]:
        """Search GitHub for the username."""
        url = f"https://github.com/{self.username}"
        response = self._make_request(url, method='GET')
        
        if response and response.status_code == 200:
            # Try to extract additional info from the page
            bio = "GitHub user"
            profile_image = f"https://github.com/{self.username}.png"
            
            if BS4_AVAILABLE:
                try:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    # Try to find bio
                    bio_elem = soup.find('div', class_='p-note')
                    if bio_elem:
                        bio = bio_elem.get_text(strip=True)[:100]
                except Exception as e:
                    logger.debug(f"Failed to parse GitHub page: {str(e)}")
            
            return {
                "platform": "GitHub",
                "url": url,
                "account_age": "Unknown",
                "profile_image": profile_image,
                "bio": bio,
                "confidence_score": 90
            }
        return None
    
    async def search_async(self) -> Optional[Dict]:
        """Search GitHub for the username (async)."""
        url = f"https://github.com/{self.username}"
        result = await self._make_request_async(url, method='GET')
        
        if result and result[0] == 200:
            # Try to extract additional info from the page
            bio = "GitHub user"
            profile_image = f"https://github.com/{self.username}.png"
            
            if BS4_AVAILABLE and result[1]:
                try:
                    soup = BeautifulSoup(result[1], 'html.parser')
                    # Try to find bio
                    bio_elem = soup.find('div', class_='p-note')
                    if bio_elem:
                        bio = bio_elem.get_text(strip=True)[:100]
                except Exception as e:
                    logger.debug(f"Failed to parse GitHub page: {str(e)}")
            
            return {
                "platform": "GitHub",
                "url": url,
                "account_age": "Unknown",
                "profile_image": profile_image,
                "bio": bio,
                "confidence_score": 90
            }
        return None


class TwitterSearcher(PlatformSearcher):
    """Search Twitter/X for username."""
    
    def search(self) -> Optional[Dict]:
        """Search Twitter/X for the username."""
        url = f"https://twitter.com/{self.username}"
        response = self._make_request(url, method='HEAD')
        
        if response and response.status_code == 200:
            return {
                "platform": "Twitter/X",
                "url": url,
                "account_age": "Unknown",
                "profile_image": "Unknown (requires authentication)",
                "bio": "Public profile (details require authentication)",
                "confidence_score": 80
            }
        return None
    
    async def search_async(self) -> Optional[Dict]:
        """Search Twitter/X for the username (async)."""
        url = f"https://twitter.com/{self.username}"
        result = await self._make_request_async(url, method='HEAD')
        
        if result and result[0] == 200:
            return {
                "platform": "Twitter/X",
                "url": url,
                "account_age": "Unknown",
                "profile_image": "Unknown (requires authentication)",
                "bio": "Public profile (details require authentication)",
                "confidence_score": 80
            }
        return None


class FacebookSearcher(PlatformSearcher):
    """Search Facebook public pages for username."""
    
    def search(self) -> Optional[Dict]:
        """Search Facebook for the username."""
        url = f"https://www.facebook.com/{self.username}"
        response = self._make_request(url, method='HEAD')
        
        if response and response.status_code == 200:
            return {
                "platform": "Facebook",
                "url": url,
                "account_age": "Unknown",
                "profile_image": "Unknown",
                "bio": "Public page or profile",
                "confidence_score": 70
            }
        return None
    
    async def search_async(self) -> Optional[Dict]:
        """Search Facebook for the username (async)."""
        url = f"https://www.facebook.com/{self.username}"
        result = await self._make_request_async(url, method='HEAD')
        
        if result and result[0] == 200:
            return {
                "platform": "Facebook",
                "url": url,
                "account_age": "Unknown",
                "profile_image": "Unknown",
                "bio": "Public page or profile",
                "confidence_score": 70
            }
        return None


class LinkedInSearcher(PlatformSearcher):
    """Search LinkedIn public profiles for username."""
    
    def search(self) -> Optional[Dict]:
        """Search LinkedIn for the username."""
        url = f"https://www.linkedin.com/in/{self.username}"
        response = self._make_request(url, method='HEAD')
        
        if response and response.status_code == 200:
            return {
                "platform": "LinkedIn",
                "url": url,
                "account_age": "Unknown",
                "profile_image": "Unknown",
                "bio": "Professional profile (details require authentication)",
                "confidence_score": 75
            }
        return None
    
    async def search_async(self) -> Optional[Dict]:
        """Search LinkedIn for the username (async)."""
        url = f"https://www.linkedin.com/in/{self.username}"
        result = await self._make_request_async(url, method='HEAD')
        
        if result and result[0] == 200:
            return {
                "platform": "LinkedIn",
                "url": url,
                "account_age": "Unknown",
                "profile_image": "Unknown",
                "bio": "Professional profile (details require authentication)",
                "confidence_score": 75
            }
        return None


class RedditSearcher(PlatformSearcher):
    """Search Reddit for username."""
    
    def search(self) -> Optional[Dict]:
        """Search Reddit for the username."""
        url = f"https://www.reddit.com/user/{self.username}"
        response = self._make_request(url, method='HEAD')
        
        if response and response.status_code == 200:
            return {
                "platform": "Reddit",
                "url": url,
                "account_age": "Unknown",
                "profile_image": "Unknown (requires API access)",
                "bio": "Reddit user profile",
                "confidence_score": 85
            }
        return None
    
    async def search_async(self) -> Optional[Dict]:
        """Search Reddit for the username (async)."""
        url = f"https://www.reddit.com/user/{self.username}"
        result = await self._make_request_async(url, method='HEAD')
        
        if result and result[0] == 200:
            return {
                "platform": "Reddit",
                "url": url,
                "account_age": "Unknown",
                "profile_image": "Unknown (requires API access)",
                "bio": "Reddit user profile",
                "confidence_score": 85
            }
        return None


class TelegramSearcher(PlatformSearcher):
    """Search Telegram public channels/groups for username."""
    
    def search(self) -> Optional[Dict]:
        """Search Telegram for the username."""
        url = f"https://t.me/{self.username}"
        response = self._make_request(url, method='HEAD')
        
        if response and response.status_code == 200:
            return {
                "platform": "Telegram",
                "url": url,
                "account_age": "Unknown",
                "profile_image": "Unknown",
                "bio": "Public channel or group",
                "confidence_score": 75
            }
        return None
    
    async def search_async(self) -> Optional[Dict]:
        """Search Telegram for the username (async)."""
        url = f"https://t.me/{self.username}"
        result = await self._make_request_async(url, method='HEAD')
        
        if result and result[0] == 200:
            return {
                "platform": "Telegram",
                "url": url,
                "account_age": "Unknown",
                "profile_image": "Unknown",
                "bio": "Public channel or group",
                "confidence_score": 75
            }
        return None


class PastebinSearcher(PlatformSearcher):
    """Search Pastebin for username mentions."""
    
    def search(self) -> Optional[Dict]:
        """Search Pastebin for the username."""
        # Check if user has a pastebin profile
        url = f"https://pastebin.com/u/{self.username}"
        response = self._make_request(url, method='HEAD')
        
        if response and response.status_code == 200:
            return {
                "platform": "Pastebin",
                "url": url,
                "account_age": "Unknown",
                "profile_image": "Unknown",
                "bio": "Pastebin user profile",
                "confidence_score": 70
            }
        return None
    
    async def search_async(self) -> Optional[Dict]:
        """Search Pastebin for the username (async)."""
        url = f"https://pastebin.com/u/{self.username}"
        result = await self._make_request_async(url, method='HEAD')
        
        if result and result[0] == 200:
            return {
                "platform": "Pastebin",
                "url": url,
                "account_age": "Unknown",
                "profile_image": "Unknown",
                "bio": "Pastebin user profile",
                "confidence_score": 70
            }
        return None


class StackOverflowSearcher(PlatformSearcher):
    """Search StackOverflow for username."""
    
    def search(self) -> Optional[Dict]:
        """Search StackOverflow for the username."""
        # StackOverflow uses numeric IDs, so we search by display name
        search_url = f"https://stackoverflow.com/users?tab=users&search={quote_plus(self.username)}"
        
        if not BS4_AVAILABLE:
            return None
            
        try:
            response = self._make_request(search_url, method='GET')
            if response and response.status_code == 200:
                # Check if any results found
                soup = BeautifulSoup(response.text, 'html.parser')
                user_cards = soup.find_all('div', class_='user-info')
                
                if user_cards:
                    return {
                        "platform": "StackOverflow",
                        "url": search_url,
                        "account_age": "Unknown",
                        "profile_image": "Unknown",
                        "bio": f"Search results for '{self.username}'",
                        "confidence_score": 65
                    }
        except Exception as e:
            logger.debug(f"StackOverflow search failed: {str(e)}")
        
        return None
    
    async def search_async(self) -> Optional[Dict]:
        """Search StackOverflow for the username (async)."""
        search_url = f"https://stackoverflow.com/users?tab=users&search={quote_plus(self.username)}"
        
        if not BS4_AVAILABLE:
            return None
            
        try:
            result = await self._make_request_async(search_url, method='GET')
            if result and result[0] == 200 and result[1]:
                # Check if any results found
                soup = BeautifulSoup(result[1], 'html.parser')
                user_cards = soup.find_all('div', class_='user-info')
                
                if user_cards:
                    return {
                        "platform": "StackOverflow",
                        "url": search_url,
                        "account_age": "Unknown",
                        "profile_image": "Unknown",
                        "bio": f"Search results for '{self.username}'",
                        "confidence_score": 65
                    }
        except Exception as e:
            logger.debug(f"StackOverflow async search failed: {str(e)}")
        
        return None


class GitHubGistsSearcher(PlatformSearcher):
    """Search GitHub Gists for username."""
    
    def search(self) -> Optional[Dict]:
        """Search GitHub Gists for the username."""
        url = f"https://gist.github.com/{self.username}"
        response = self._make_request(url, method='HEAD')
        
        if response and response.status_code == 200:
            return {
                "platform": "GitHub Gists",
                "url": url,
                "account_age": "Unknown",
                "profile_image": f"https://github.com/{self.username}.png",
                "bio": "GitHub Gists profile",
                "confidence_score": 80
            }
        return None
    
    async def search_async(self) -> Optional[Dict]:
        """Search GitHub Gists for the username (async)."""
        url = f"https://gist.github.com/{self.username}"
        result = await self._make_request_async(url, method='HEAD')
        
        if result and result[0] == 200:
            return {
                "platform": "GitHub Gists",
                "url": url,
                "account_age": "Unknown",
                "profile_image": f"https://github.com/{self.username}.png",
                "bio": "GitHub Gists profile",
                "confidence_score": 80
            }
        return None


class NamechkSearcher(PlatformSearcher):
    """Namechk reference for comprehensive username availability check."""
    
    def search(self) -> Optional[Dict]:
        """Provide Namechk reference for the username."""
        url = f"https://namechk.com/{self.username}"
        
        return {
            "platform": "Namechk",
            "url": url,
            "account_age": "N/A",
            "profile_image": "N/A",
            "bio": "Username availability check across 100+ platforms",
            "confidence_score": 50
        }


class GoogleSearcher(PlatformSearcher):
    """Google custom search reference for username."""
    
    def search(self) -> Optional[Dict]:
        """Provide Google search reference for the username."""
        query = quote_plus(f'"{self.username}" social media profile')
        url = f"https://www.google.com/search?q={query}"
        
        return {
            "platform": "Google Search",
            "url": url,
            "account_age": "N/A",
            "profile_image": "N/A",
            "bio": f"Google search results for '{self.username}'",
            "confidence_score": 60
        }


class BingSearcher(PlatformSearcher):
    """Bing custom search reference for username."""
    
    def search(self) -> Optional[Dict]:
        """Provide Bing search reference for the username."""
        query = quote_plus(f'"{self.username}" profile')
        url = f"https://www.bing.com/search?q={query}"
        
        return {
            "platform": "Bing Search",
            "url": url,
            "account_age": "N/A",
            "profile_image": "N/A",
            "bio": f"Bing search results for '{self.username}'",
            "confidence_score": 60
        }


def search_username(username: str, use_async: bool = False) -> List[Dict]:
    """
    Comprehensive username search across multiple platforms.
    
    This function searches for a given username across various platforms and
    public sources, returning detailed information about found profiles.
    
    Args:
        username: The username to search for
        use_async: Whether to use asynchronous search (faster, requires aiohttp)
        
    Returns:
        List of dictionaries containing platform data with the following structure:
        [
            {
                "platform": str,           # Platform name
                "url": str,               # Profile or search URL
                "account_age": str,       # Account age if available
                "profile_image": str,     # Profile image URL if available
                "bio": str,               # Bio snippet if available
                "confidence_score": int   # Confidence score (0-100)
            },
            ...
        ]
        
    Raises:
        ValueError: If username is invalid
        
    Examples:
        >>> results = search_username("example_user")
        >>> for result in results:
        ...     print(f"{result['platform']}: {result['url']}")
        >>> # Async version (faster)
        >>> results = search_username("example_user", use_async=True)
    """
    # Normalize username - handle dict return value
    norm_result = normalize_username(username)
    if isinstance(norm_result, dict):
        normalized_username = norm_result.get('normalized_username', username)
    else:
        normalized_username = norm_result
    
    # Validate username - handle dict return value
    validation_result = validate_username(normalized_username)
    if isinstance(validation_result, dict):
        is_valid = validation_result.get('valid', False)
        if not is_valid:
            logger.warning(f"Username '{username}' may not be valid: {validation_result.get('notes', 'Unknown reason')}")
    
    if not normalized_username:
        raise ValueError("Username cannot be empty after normalization")
    
    logger.info(f"Starting comprehensive search for username: {normalized_username}")
    
    # Use async if requested and available
    if use_async and ASYNC_AVAILABLE:
        # Run async version
        return asyncio.run(search_username_async(normalized_username))
    else:
        # Run synchronous version
        return _search_username_sync(normalized_username)


def _search_username_sync(normalized_username: str) -> List[Dict]:
    """Synchronous implementation of username search."""
    # Initialize rate limiter (1 request per second to be respectful)
    rate_limiter = RateLimiter(requests_per_second=1.0)
    
    # Define all platform searchers
    searchers = [
        InstagramSearcher(normalized_username),
        GitHubSearcher(normalized_username),
        TwitterSearcher(normalized_username),
        FacebookSearcher(normalized_username),
        LinkedInSearcher(normalized_username),
        RedditSearcher(normalized_username),
        TelegramSearcher(normalized_username),
        PastebinSearcher(normalized_username),
        StackOverflowSearcher(normalized_username),
        GitHubGistsSearcher(normalized_username),
        NamechkSearcher(normalized_username),
        GoogleSearcher(normalized_username),
        BingSearcher(normalized_username),
    ]
    
    results = []
    
    # Search each platform
    for searcher in searchers:
        platform_name = searcher.__class__.__name__.replace('Searcher', '')
        logger.debug(f"Searching {platform_name}...")
        
        try:
            # Respect rate limits
            rate_limiter.wait()
            
            # Perform search
            result = searcher.search()
            
            if result:
                results.append(result)
                logger.info(f"✓ Found on {result['platform']}")
            else:
                logger.debug(f"✗ Not found on {platform_name}")
                
        except Exception as e:
            logger.error(f"Error searching {platform_name}: {str(e)}")
            continue
    
    logger.info(f"Search complete. Found {len(results)} results for '{normalized_username}'")
    
    return results


async def search_username_async(normalized_username: str) -> List[Dict]:
    """
    Asynchronous username search across multiple platforms.
    
    This is significantly faster than synchronous search as it performs
    searches concurrently across all platforms.
    
    Args:
        normalized_username: The normalized username to search for
        
    Returns:
        List of dictionaries containing platform data
    """
    if not ASYNC_AVAILABLE:
        logger.warning("Async support not available. Falling back to synchronous search.")
        return _search_username_sync(normalized_username)
    
    logger.info(f"Starting async search for username: {normalized_username}")
    
    # Initialize rate limiter for async
    rate_limiter = RateLimiter(requests_per_second=2.0)  # Can be faster with async
    
    # Define all platform searchers
    searchers = [
        InstagramSearcher(normalized_username),
        GitHubSearcher(normalized_username),
        TwitterSearcher(normalized_username),
        FacebookSearcher(normalized_username),
        LinkedInSearcher(normalized_username),
        RedditSearcher(normalized_username),
        TelegramSearcher(normalized_username),
        PastebinSearcher(normalized_username),
        StackOverflowSearcher(normalized_username),
        GitHubGistsSearcher(normalized_username),
        NamechkSearcher(normalized_username),
        GoogleSearcher(normalized_username),
        BingSearcher(normalized_username),
    ]
    
    results = []
    
    # Create async tasks for all searchers
    async def search_with_rate_limit(searcher):
        """Helper to search with rate limiting."""
        platform_name = searcher.__class__.__name__.replace('Searcher', '')
        logger.debug(f"Searching {platform_name}...")
        
        try:
            # Respect rate limits
            await rate_limiter.wait_async()
            
            # Perform async search
            result = await searcher.search_async()
            
            if result:
                logger.info(f"✓ Found on {result['platform']}")
                return result
            else:
                logger.debug(f"✗ Not found on {platform_name}")
                return None
                
        except Exception as e:
            logger.error(f"Error searching {platform_name}: {str(e)}")
            return None
    
    # Run all searches concurrently
    search_tasks = [search_with_rate_limit(searcher) for searcher in searchers]
    search_results = await asyncio.gather(*search_tasks, return_exceptions=True)
    
    # Filter out None values and exceptions
    for result in search_results:
        if result and not isinstance(result, Exception):
            results.append(result)
    
    logger.info(f"Async search complete. Found {len(results)} results for '{normalized_username}'")
    
    return results


def main():
    """
    Main function to demonstrate the module's capability.
    
    This function can be run directly to test the username search functionality.
    Demonstrates both synchronous and asynchronous search modes.
    """
    import sys
    
    print("="*70)
    print("InfinityTrace - Pro-Level Username Search Module")
    print("="*70)
    print()
    
    # Check command line arguments
    test_username = "github"  # Default test username
    use_async = False
    
    if len(sys.argv) > 1:
        test_username = sys.argv[1]
    if len(sys.argv) > 2 and sys.argv[2] == "--async":
        use_async = True
    
    print(f"Testing with username: {test_username}")
    print(f"Mode: {'Asynchronous' if use_async else 'Synchronous'}")
    if use_async and not ASYNC_AVAILABLE:
        print("Warning: aiohttp not available. Install it for async support: pip install aiohttp")
        print("Falling back to synchronous mode...")
        use_async = False
    print("-"*70)
    print()
    
    try:
        # Perform search
        import time
        start_time = time.time()
        results = search_username(test_username, use_async=use_async)
        elapsed_time = time.time() - start_time
        
        # Display results
        if results:
            print(f"Found {len(results)} results in {elapsed_time:.2f} seconds:\n")
            
            for i, result in enumerate(results, 1):
                print(f"{i}. Platform: {result['platform']}")
                print(f"   URL: {result['url']}")
                print(f"   Account Age: {result['account_age']}")
                print(f"   Profile Image: {result['profile_image']}")
                print(f"   Bio: {result['bio']}")
                print(f"   Confidence Score: {result['confidence_score']}/100")
                print()
        else:
            print("No results found.")
        
        print("-"*70)
        print(f"Test completed successfully in {elapsed_time:.2f} seconds!")
        print()
        print("Usage:")
        print(f"  python {sys.argv[0]} <username>           # Synchronous search")
        print(f"  python {sys.argv[0]} <username> --async   # Asynchronous search (faster)")
        
    except Exception as e:
        logger.error(f"Test failed: {str(e)}")
        print(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
