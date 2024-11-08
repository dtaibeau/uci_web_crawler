import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, urlunparse
import logging
from hashlib import md5
from collections import Counter


MAX_DEPTH = 8
MIN_WORD_COUNT = 50

unique_urls = set()
subdomain_counter = Counter()
words_counter = Counter()
page_hashes = set()

longest_page_info = {
    "url": None,
    "word_count": 0
}

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

allowed_domains = [
    "ics.uci.edu",
    "cs.uci.edu",
    "informatics.uci.edu",
    "stat.uci.edu",
    "today.uci.edu"
]

allowed_paths = {
    "today.uci.edu": ["/department/information_computer_sciences"]
}

robots_cache = {
    "ics.uci.edu": {"/": True},  
    "cs.uci.edu": {"/": True},
    "informatics.uci.edu": {
        "/wp-admin/": False,
        "/wp-admin/admin-ajax.php": True,
        "/research/": False,
    },
    "stat.uci.edu": {
        "/wp-admin/": False,
    },
    "today.uci.edu": {"/department/information_computer_sciences/": True},
}


def is_similar_content(content):
    """
    Checks if the page content is similar to previously processed content.
    Uses MD5 hashing to detect duplicate content.

    Args:
        content (str): The text content of the page.

    Returns:
        bool: True if similar content was detected, otherwise False.
    """
    # Calculate a hash of the content
    content_hash = md5(content.encode('utf-8')).hexdigest()
    
    if content_hash in page_hashes:
        logger.info("Detected similar content. Skipping page.")
        return True
    
    # Add this page's hash to the set for future comparisons
    page_hashes.add(content_hash)
    return False


def can_fetch(url):
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path

    # check if the domain matches any of the allowed domains in robots_cache
    for allowed_domain in robots_cache.keys():
        if domain.endswith(allowed_domain):
            path_rules = robots_cache[allowed_domain]

            # check for specific path permissions
            for rule, is_allowed in path_rules.items():
                if path.startswith(rule):
                    return is_allowed  # return True if allowed, False if disallowed

            # if no specific rule matches, assume the default rule (usually allow)
            return path_rules.get("/", True)
    
    return False


def is_empty_page(content):
    soup = BeautifulSoup(content, 'lxml')
    text = soup.get_text(strip=True)
    return len(text) == 0


def is_low_information(content):
    soup = BeautifulSoup(content, 'lxml')

    if isinstance(content, bytes):
        content = content.decode('utf-8', errors='ignore')

    # extract words
    words = re.findall(r'\w+', content)
    
    # find urls
    hyperlinks = re.findall(r'https?://\S+|www\.\S+', content)
    
    # if less than min words and urls < 5 = low infdo page
    if len(words) < MIN_WORD_COUNT and len(hyperlinks) < 5:
        return True

    # Check for presence of key tags
    significant_elements = soup.find_all(['p', 'h1', 'h2', 'h3', 'img'])
    if significant_elements:
        return False
    
    return True


def scraper(url, resp, frontier):
    """
    Extracts and filters valid URLs from a page's response,
    handling cache server error codes (600-608) and updating report metrics.

    Args:
        url (str): The URL being processed.
        resp (utils.response.Response): The response object with the page content.
        frontier (Frontier): The frontier to mark URLs as complete.

    Returns:
        list: A list of valid URLs for further crawling.
    """
    # step 1: check response status first to skip invalid pages
    if resp is None or resp.status in {404, 403, 600, 601, 602, 603, 604, 605, 606, 607, 608}:
        logger.info(f"Skipping URL due to status {resp.status}: {url}")
        frontier.mark_url_complete(url)
        return []

    # step 2: handle potential traps and validate if the URL can be fetched
    if not is_valid(url):
        logger.info(f"Skipping potential trap or invalid URL: {url}")
        frontier.mark_url_complete(url)
        return []
    
    # if response is invalid or no content is available
    if resp.status != 200 or not resp.raw_response:
        handle_cache_server_error(url, resp.status, frontier)
        logger.info(f"Request unsuccessful for {url}, returning empty list")
        frontier.mark_url_complete(url)
        return []
    
    # check if response = valid
    content = resp.raw_response.content if resp.raw_response else b""
    if isinstance(content, bytes):
        content = content.decode('utf-8', errors='ignore')

    if is_empty_page(content) or is_low_information(content) or is_similar_content(content):
        logger.info(f"Skipping dead, similar, or low-information URL: {url}")
        frontier.mark_url_complete(url)
        return []
    
    # update report metrics if page is unique
    if is_unique_page(url):
        logger.info(f"Adding unique page: {url}")
        longest_page(url, content)
        common_words_count(content)
        num_subdomains(url)

    # extract links from page content
    links = extract_next_links(url, resp)
    for link in links:
            if calculate_depth(link) < MAX_DEPTH:
                frontier.add_url(link)
            else:
                logger.info(f"Skipping {link} - Exceeded max depth")

    return links if links else []


def handle_cache_server_error(url, status, frontier):
    """
    Handles specific cache server error codes (600-608).

    Args:
        url (str): The URL that caused the error.
        resp (utils.response.Response): The response object with the error code.
        frontier (Frontier): The frontier to mark URLs as complete.
    """
    if not isinstance(url, str):
        logger.error("Expected URL as a string but got something else.")
        return
    
    if status == 600:
        logger.error(f"Malformed request for URL: {url}")
    elif status == 601:
        logger.error(f"Download exception for URL: {url}.")
    elif status == 602:
        logger.error(f"Spacetime server failure for URL: {url}")
    elif status == 603:
        logger.info(f"Invalid scheme for URL: {url} (must be http or https)")
    elif status == 604:
        logger.info(f"Domain not within specification for URL: {url}")
    elif status == 605:
        logger.info(f"Invalid file extension for URL: {url}")
    elif status == 606:
        logger.error(f"Exception in parsing URL: {url}")
    elif status == 607:
        logger.info(f"Content too big for URL: {url}.")
    elif status == 608:
        logger.info(f"Denied by robots.txt rules for URL: {url}")
    elif status == 404:
        logger.info(f"404 NOT FOUND: {url}")
    elif status == 403:
        logger.info(f"403 ERROR: {url}")
    elif status == 401:
        logger.info(f"401 ERROR: Unauthorized {url}")
    
    frontier.mark_url_complete(url)

def extract_next_links(url, resp):
    """
    Extracts all URLs from the HTML content of the response, ensuring they are unique.
    
    Args:
        url (str): The URL being processed.
        resp (utils.response.Response): The response object with the page content.
    
    Returns:
        list: A list of unique, valid URLs found in the page.
    """

    soup = BeautifulSoup(resp.raw_response.content, 'lxml')
    links = set()

    # Extract and validate hyperlinks
    for anchor in soup.find_all('a', href=True):
        link = urljoin(url, urlparse(anchor['href'])._replace(fragment='').geturl())
        if is_valid(link):
            links.add(link)
            #logger.info(f"Valid link added: {link}")

    return list(links)

def calculate_depth(url):
    """
    Calculate the depth of the URL based on the number of slashes in its path.

    Args:
        url (str): The URL to calculate depth for.

    Returns:
        int: The depth of the URL.
    """
    return urlparse(url).path.count('/')

def detect_potential_trap(url):
    """
    Detects potential traps based on URL patterns, repetitive query parameters, or known traps.

    Args:
        url (str): The URL to check.

    Returns:
        bool: True if the URL is a potential trap, False otherwise.
    """
    repetitive_patterns = ["do=media", "tab_files", "image=", "tab_details", "ns=", "rev=", "do=diff",
        "tribe__ecp_custom_", "filter%5Bunits%5D", "&ical=1", "?ical=", "event/", "events/", "announce:", "services:", "accounts:", 
        "virtual_environments:", "group:", "support:"]
    
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Apply additional filtering for specific domains
    if domain in {"archive.ics.uci.edu", "ics.uci.edu", "swiki.ics.uci.edu" }:
        if any(pattern in url for pattern in repetitive_patterns):
            logger.info(f"Skipping potential media trap URL: {url}")
            return True
    
    # General repetitive patterns and query count check
    general_patterns = ["/?", "&page=", "&start=", "&filter=", "&sort="]
    if any(pattern in url for pattern in general_patterns):
        return True
    
    query_count = parsed_url.query.count('&')
    if query_count > 5:
        return True
    
    return False

def is_valid(url):
    """
    Validates if a URL should be crawled.
    
    Args:
        url (str): The URL to check.
    
    Returns:
        bool: True if the URL is valid for crawling, False otherwise.
    """
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path
        query = parsed.query

        # 7. Ensure URL uses HTTP or HTTPS
        if parsed.scheme not in {"http", "https"}:
            return False

        # 1. Check domain and specific path for today.uci.edu
        if not any(domain == allowed_domain or domain.endswith("." + allowed_domain) for allowed_domain in allowed_domains):
            return False
        
        # Path restriction for today.uci.edu
        if domain == "today.uci.edu":
            if not any(path.startswith(allowed_path) for allowed_path in allowed_paths.get(domain, [])):
                return False

        # 2. Block specific date-based archive URLs on www.informatics.uci.edu
        if domain == "www.informatics.uci.edu" and re.search(r"/\d{4}/\d{2}/?$", path):
            return False
        
        date_pattern = re.compile(r'/\d{4}/\d{2}/\d{2}/')  # Matches /YYYY/MM/DD/ or -based paths
        if date_pattern.search(url):
            return False    
        
        if domain == "www.flamingo.ics.uci.edu":
            return False

        # 3. Check robots.txt compliance
        if not can_fetch(url):
            logger.info(f"Blocked by robots.txt: {url}")
            return False
        
        # 9. Exclude URLs containing trap terms or specific patterns
        trap_terms = [
            "page_id", "/pdf/", "/tag/", "/page/", "/category/", "/paged=", "/?tag", "/archive/",
            "partnerships_posts", "institutes_centers", "research_areas_ics",
            "calendar/event?action=template", "/?ical=1", "/day/", "/week/", "/month/",
            "eventdisplay=past", "tribe-bar-date", "post_type=tribe_events",
            "/events/", "/event/", "/wp-login.php", "action=login", "action=edit",
            "/wiki/", "/wiki?", "/wikiword", "/wikisandbox", "/pmwiki", "cookbook",
            "/sitemap", "csdl/trans", "ieeexplore", "/petko", "/pmichaud", "wikivoyage",
            "en.wiktionary", "/indexdot", "home?action=login", "google.com/calendar",
            "linkedin.com/share", "twitter.com/share", "facebook.com/sharer",
            "zoom.us", "docs.google.com", "drive.google.com", "youtu.be", "youtube.com",
            "confirmsubscription", "forms.gle", "subscribe", "google.com/maps", 
            "calendar.google.com", "/~seal/projects/", "/wp-login.php", "redirect_to=", 
            "index.php?p=", "?filter%5B", "%5B", "jgarcia/", "tab_files", "do=media", "tab_details", "ns=", "image=", "upload",
            "backlinks", "commit", "html_oopsc", "password", "login", "phpmyadmin", "upname=", "/download",
            "doku.php", "follow-us", "private_downloads", ".md", "PageNotFound", "/assignments", "datasets?search",
            "letter-of-recommendation-workshop", "/junkyard/", "Classes-2008F", "/sw/clsmtools?", "/Lectures/",
            "~eppstein", "flamingo", "~aces/", "/releases/", "Classes-CS178-Notes/", "/patient-",
            "~thornton", "/data/", "ics139ws2014", "/photos/", "/grades/", "/javacourse/", "/SAFIRE/", "/teaching/",
            "~dechter/publications/", "seminar-series/", "faculty-profiles/", "student-profiles/", "undergraduate-alumni-spotlights/"
            "explore/", "impact/", "randomSmiles100K", "ooad/", "diss/","mailman/admin/", "/colorful-reading", "~fowlkes/publications2.html"
        ]

        # 4. Detect traps
        if detect_potential_trap(url):
            return False

        # 5. Exclude URLs with common trap query patterns
        if "filter%5B" in query or "%5B" in query:
            logger.info("filter%5B trap detected")
            return False

        # 6. Skip static content or media files based on path patterns
        if "wp-content/uploads" in path:
            logger.info(f"Skipping static content URL: {url}")
            return False

        # 8. Block large file types by extension
        large_file_extensions = (
            ".pdf", ".docx", ".mp4", ".mp3", ".mpg", ".avi", ".mov", ".zip", ".rar", ".pps", ".ppsx", ".pptx", ".ppt"
        )
        if any(url.lower().endswith(ext) for ext in large_file_extensions):
            return False
        
        if any(term in url.lower() for term in trap_terms):
            return False

        # 10. Block URLs ending with specific numeric patterns (trap for certain publications)
        if re.search(r'/r\d+\.html$', url.lower()):
            return False
        
        if re.search(r'/ics_x33/\w+\.html$', url.lower()):
            return False

        # 11. Exclude non-HTML file types
        if re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico|png|tiff?|mid|mp2|mp3|mp4|wav|avi|mov|"
            r"mpeg|ram|m4v|mkv|ogg|ogv|pdf|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names|"
            r"data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso|epub|dll|cnf|tgz|sha1|"
            r"thmx|mso|arff|rtf|jar|csv|rm|smil|wmv|swf|wma|zip|rar|gz)$",
            path.lower()
        ):
            return False

        return True

    except Exception as e:
        logger.error(f"Error validating URL: {url}, {e}")
        return False

 
def is_unique_page(url):
    parsed_url = urlparse(url)
    normalized_url = urlunparse(parsed_url._replace(fragment='')).lower()  # Normalize URL

    if is_valid(normalized_url) and normalized_url not in unique_urls:
        unique_urls.add(normalized_url)
        return True
    else:
        logger.info(f"Duplicate or invalid URL skipped: {normalized_url}")
        return False

def num_unique_pages():
    """
    Returns the number of unique pages crawled.
    
    Returns:
        int: Number of unique pages.
    """
    return len(unique_urls)


def longest_page(url, content):
    """
    Updates the longest page information based on word count, excluding HTML markup.
    
    Args:
        url (str): The URL of the page.
        content (str): The HTML content of the page.
    """
    # Parse content to remove HTML tags
    soup = BeautifulSoup(content, 'html.parser')
    text = soup.get_text()  # Extract only text content
    
    # Count words in the plain text
    words = re.findall(r'\w+', text.lower())
    word_count = len(words)
    
    # Update longest page info if this page has more words
    if word_count > longest_page_info["word_count"]:
        longest_page_info["url"] = url
        longest_page_info["word_count"] = word_count


def common_words_count(content):
    """
    Updates the global word counter with non-stop words found in the content.
    
    Args:
        content (str): The textual content of the page.
    """

    # includes english stop words and html tags = add little to no value 
    stop_words = {
    "a", "about", "above", "after", "again", "against", "all", "am", "an", "and", "any", "are", "aren't", "as", "at", 
    "be", "because", "been", "before", "being", "below", "between", "both", "but", "by", "can't", "cannot", "could", 
    "couldn't", "did", "didn't", "do", "does", "doesn't", "doing", "don't", "down", "during", "each", "few", "for", 
    "from", "further", "had", "hadn't", "has", "hasn't", "have", "haven't", "having", "he", "he'd", "he'll", "he's", 
    "her", "here", "here's", "hers", "herself", "him", "himself", "his", "how", "how's", "i", "i'd", "i'll", "i'm", 
    "i've", "if", "in", "into", "is", "isn't", "it", "it's", "its", "itself", "let's", "me", "more", "most", "mustn't", 
    "my", "myself", "no", "nor", "not", "of", "off", "on", "once", "only", "or", "other", "ought", "our", "ours", 
    "ourselves", "out", "over", "own", "same", "shan't", "she", "she'd", "she'll", "she's", "should", "shouldn't", 
    "so", "some", "such", "than", "that", "that's", "the", "their", "theirs", "them", "themselves", "then", "there", 
    "there's", "these", "they", "they'd", "they'll", "they're", "they've", "this", "those", "through", "to", "too", 
    "under", "until", "up", "very", "was", "wasn't", "we", "we'd", "we'll", "we're", "we've", "were", "weren't", 
    "what", "what's", "when", "when's", "where", "where's", "which", "while", "who", "who's", "whom", "why", "why's", 
    "with", "won't", "would", "wouldn't", "you", "you'd", "you'll", "you're", "you've", "your", "yours", "yourself", 
    "yourselves", "class", "div", "href", "color", "td", "span", "id", "https", "css", "font", "script", "style", "p", 
    "type", "var", "elementor", "menu", "preset", "data", "page", "js", "li", "content", "background", "text", "wp", 
    "primary__list", "primary__action", "important", "gradient", "child", "depth", "t", "e", "c", "vivid", "tr",
    }

    # excluding digits and special characters, filter out stop words and non alphanum words < 3
    words = re.findall(r'\b[a-zA-Z]{3,}\b|\b\w{3,}\b', content.lower())
    filtered_words = [word for word in words if word not in stop_words and len(word) >= 3]
    
    # Update global counter with filtered words
    words_counter.update(filtered_words)
  
    

def num_subdomains(url):
    """
    Updates the subdomain counter based on the URL, with specific checks for allowed subdomains.
    
    Args:
        url (str): The URL to check for subdomains.
    """
    parsed = urlparse(url)
    if any(domain in parsed.netloc for domain in ["ics.uci.edu", "cs.uci.edu", "informatics.uci.edu", "stat.uci.edu"]) or \
       (parsed.netloc == "today.uci.edu" and parsed.path.startswith("/department/information_computer_sciences")):
        
        subdomain = parsed.netloc
        subdomain_counter[subdomain] += 1

def generate_report():
    """
    Generates a report based on the crawled data and saves it to a file.
    """
    report_path = "crawler_report.txt"
    
    with open(report_path, "w") as report_file:
        report_file.write(f"Number of unique pages: {num_unique_pages()}\n\n")
        
        report_file.write(f"Longest page:\n")
        report_file.write(f"URL: {longest_page_info['url']}\n")
        report_file.write(f"Word count: {longest_page_info['word_count']}\n\n")
        
        report_file.write("50 Most Common Words:\n")
        for word, count in words_counter.most_common(50):
            report_file.write(f"{word}: {count}\n")
        
        report_file.write("\nSubdomains and Counts:\n")
        for subdomain, count in sorted(subdomain_counter.items()):
            report_file.write(f"{subdomain}: {count}\n")
    
    logger.info(f"Report generated and saved to {report_path}")

