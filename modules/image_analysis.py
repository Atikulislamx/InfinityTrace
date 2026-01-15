import os
import hashlib
import json
import logging

# Optional dependencies with graceful fallback
try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    logging.warning("PIL/Pillow not available - image analysis features limited")

try:
    import imagehash
    IMAGEHASH_AVAILABLE = True
except ImportError:
    IMAGEHASH_AVAILABLE = False
    logging.warning("imagehash not available - perceptual hashing disabled")

try:
    import exifread
    EXIFREAD_AVAILABLE = True
except ImportError:
    EXIFREAD_AVAILABLE = False
    logging.warning("exifread not available - EXIF metadata extraction disabled")

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    logging.warning("requests not available - image downloads disabled")

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

class ImageAnalysis:
    """
    Advanced Image Intelligence Module for OSINT.
    """

    def __init__(self):
        pass

    @staticmethod
    def normalize_image(image_input):
        """
        Normalize and preprocess the image safely.

        Args:
            image_input (str): URL or local file path of the image.

        Returns:
            Image: Preprocessed Pillow Image object.
        """
        if not PIL_AVAILABLE:
            raise ImportError("PIL/Pillow is required for image processing. Install with: pip install Pillow")
        
        if image_input.startswith("http"):
            if not REQUESTS_AVAILABLE:
                raise ImportError("requests library is required for downloading images. Install with: pip install requests")
            logging.info("Downloading image from URL...")
            response = requests.get(image_input, stream=True)
            response.raise_for_status()
            return Image.open(response.raw).convert("RGB")
        elif os.path.exists(image_input):
            logging.info("Loading image from local path...")
            return Image.open(image_input).convert("RGB")
        else:
            raise ValueError("Invalid input: provide a URL or valid local image path.")

    @staticmethod
    def generate_hashes(image):
        """
        Generate perceptual hashes (pHash, aHash, dHash).

        Args:
            image (Image): Preprocessed Pillow Image object.

        Returns:
            dict: Dictionary containing perceptual hashes.
        """
        if not IMAGEHASH_AVAILABLE:
            logging.warning("imagehash not available - returning empty hashes")
            return {"pHash": None, "aHash": None, "dHash": None}
        
        logging.info("Generating perceptual hashes...")
        hashes = {
            "pHash": str(imagehash.phash(image)),
            "aHash": str(imagehash.average_hash(image)),
            "dHash": str(imagehash.dhash(image)),
        }
        return hashes

    @staticmethod
    def perform_reverse_image_search(hashes):
        """
        Mock reverse image search using public engines for manual analysis.

        Args:
            hashes (dict): Perceptual hashes of the image.

        Returns:
            list: List of dictionaries containing search engine URLs.
        """
        logging.info("Providing reverse image search links...")
        engines = [
            {"site": "Google Images", "link": "https://images.google.com/"},
            {"site": "TinEye", "link": "https://tineye.com/"},
            {"site": "Yandex Images", "link": "https://yandex.com/images/"},
        ]
        return engines

    @staticmethod
    def detect_stock_images(hashes):
        """
        Mock stock image detection using perceptual hashes.

        Args:
            hashes (dict): Perceptual hashes of the image.

        Returns:
            bool: Whether the image is likely a stock image.
        """
        logging.info("Checking for stock image usage...")
        # Placeholder logic (integration with TinEye or other APIs required)
        return False

    @staticmethod
    def estimate_ai_generated_probability(image):
        """
        Mock estimation of AI-generated image probability.

        Args:
            image (Image): Preprocessed Pillow Image object.

        Returns:
            float: Probability [0-1] of the image being AI-generated.
        """
        logging.info("Estimating probability of AI-generated image...")
        # Placeholder for real API integration
        return 0.0

    @staticmethod
    def extract_exif_metadata(image_path):
        """
        Extract EXIF metadata from the image.

        Args:
            image_path (str): Local file path of the image.

        Returns:
            dict: EXIF metadata.
        """
        if not EXIFREAD_AVAILABLE:
            logging.warning("exifread not available - skipping EXIF extraction")
            return {}
        
        if not os.path.exists(image_path):
            logging.warning(f"Image path does not exist: {image_path}")
            return {}
        
        logging.info("Extracting EXIF metadata...")
        try:
            with open(image_path, "rb") as image_file:
                tags = exifread.process_file(image_file, details=False)
                return {tag: str(tags[tag]) for tag in tags}
        except Exception as e:
            logging.error(f"Failed to extract EXIF: {e}")
            return {}

    @staticmethod
    def detect_cross_platform_reuse(hashes):
        """
        Mock detection of cross-platform image reuse.

        Args:
            hashes (dict): Perceptual hashes of the image.

        Returns:
            int: Estimated number of reuse instances.
        """
        logging.info("Detecting cross-platform image reuse...")
        # Placeholder for real integration
        return 0

    @staticmethod
    def compute_image_risk_score(stock_image, ai_generated_probability, reuse_count):
        """
        Compute the overall risk score for the image.

        Args:
            stock_image (bool): Flag indicating stock image detection.
            ai_generated_probability (float): Probability of AI generation.
            reuse_count (int): Cross-platform reuse count.

        Returns:
            dict: Risk score and level.
        """
        logging.info("Computing image risk score...")
        score = 0

        # Assign weights to each factor
        if stock_image:
            score += 30
        score += int(ai_generated_probability * 50)
        score += min(reuse_count * 5, 20)

        risk_level = "LOW"
        if score > 80:
            risk_level = "HIGH"
        elif score > 50:
            risk_level = "MEDIUM"

        return {"image_risk_score": score, "risk_level": risk_level}

    def analyze_image(self, image_input):
        """
        Perform OSINT-based analysis on the given image.

        Args:
            image_input (str): URL or local file path of the image.

        Returns:
            dict: Analysis results.
        """
        logging.info("Starting analysis on image...")
        results = {}
        try:
            image = self.normalize_image(image_input)
            image_path = (
                image_input
                if os.path.exists(image_input)
                else ImageAnalysis.cache_image(image, image_input)
            )

            # Generate perceptual hashes
            hashes = self.generate_hashes(image)
            results["hashes"] = hashes

            # Reverse image search links
            results["reverse_image_search"] = self.perform_reverse_image_search(hashes)

            # Stock image detection
            results["stock_image"] = self.detect_stock_images(hashes)

            # AI-generated image probability
            results["ai_generated_probability"] = self.estimate_ai_generated_probability(image)

            # EXIF metadata
            results["exif_metadata"] = self.extract_exif_metadata(image_path)

            # Cross-platform image reuse
            results["image_reuse_count"] = self.detect_cross_platform_reuse(hashes)

            # Risk score
            risk_score = self.compute_image_risk_score(
                results["stock_image"],
                results["ai_generated_probability"],
                results["image_reuse_count"],
            )
            results.update(risk_score)

        except Exception as e:
            logging.error(f"Error analyzing image: {e}")
            results["error"] = str(e)

        return results

    @staticmethod
    def cache_image(image, image_url):
        """
        Save the downloaded image locally for further processing.

        Args:
            image (Image): Pillow Image object.
            image_url (str): Original image URL.

        Returns:
            str: Local file path to the saved image.
        """
        logging.info("Caching image locally...")
        hashed_name = hashlib.md5(image_url.encode()).hexdigest()
        local_path = os.path.join("/tmp", f"{hashed_name}.jpg")
        image.save(local_path)
        return local_path


# === Wrapper function for infinitytrace.py compatibility ===
def check_image(username: str) -> list:
    """
    Wrapper function for image analysis based on username.
    Returns list of dictionaries with image analysis results.
    
    Note: This is a placeholder implementation since actual image analysis
    requires an image URL or path, not just a username.
    """
    # For now, return an empty list as we don't have images associated with username
    # In a full implementation, this would search for profile images by username
    logging.info(f"Image analysis requested for username: {username}")
    return []


# Example usage:
if __name__ == "__main__":
    analysis = ImageAnalysis()
    input_image = "https://example.com/image.jpg"  # Replace with actual URL or path
    result = analysis.analyze_image(input_image)
    print(json.dumps(result, indent=4))
