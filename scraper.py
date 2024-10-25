import re
from bs4 import BeautifulSoup
from urllib.parse import urlparse

MAX_DEPTH = 5

def scraper(url, resp):
    """
    Extracts and filters valid URLs from a page's response.

    Args:
        url (str): The URL being processed.
        resp (utils.response.Response): The response object with the page content.

    Returns:
        list: A list of valid URLs for further crawling.
    """
    links = extract_next_links(url, resp)
    valid_links = []
    for link in links:
        if is_valid(link):
            depth = url.count('/')  # simple heuristic for depth
            if depth < MAX_DEPTH:
                valid_links.append(link)
    return valid_links

def extract_next_links(url, resp):
    """
    Extracts all URLs from the HTML content of the response.

    Args:
        url (str): The URL being processed.
        resp (utils.response.Response): The response with the page content.

    Returns:
        list: A list of URLs found in the page.
    """
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content
    
    # if request unsuccessful, return empty list
    if resp.status != 200 or resp.raw_response is None:
        print('request unsuccessful, returning empty list')
        return []
    
    # otherwise, parse through raw HTML from response obj
    soup = BeautifulSoup(resp.raw_response.content, 'html.parser')
    links = []

    # extract all valid hyperlinks (<a> href="...")
    for anchor in soup.find_all('a', href=True):
        link = anchor['href']

        # normalize link (gets rid of #'...' at end of url)
        link = urlparse(link)._replace(fragment='').geturl()
        links.append(link)    
    return links

def is_valid(url):
    """
    Validates if a URL should be crawled.

    Args:
        url (str): The URL to check.

    Returns:
        bool: True if the URL is valid for crawling, False otherwise.
    """
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.
    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False
        
        # urls with certain dynamic patterns
        if 'filter%5B' in url.lower() or 'filter[' in url.lower():
            return False
        
        # date patterns (/2021/05/25/)
        if re.search(r'/\d{4}/\d{2}/\d{2}/', url):
            return False
        
        if "tribe__ecp_custom" in parsed.query:
            return False

        # filter out traps: calendar, wiki, login, edit, and pagination URLs
        if any(term in url.lower() for term in [
            "/tag/",
            "/page/",
            "/category/",
            "/paged=",
            "/tag/",
            "/?tag",
            "/archive/"
            "partnerships_posts",
            "institutes_centers",
            "research_areas_ics"
            "calendar/event?action=template",
            "/?ical=1",
            "/day/",
            "/week/",
            "/month/",
            "eventdisplay=past",
            "tribe-bar-date",
            "paged=",
            "post_type=tribe_events",
            "/events/"
            "action=login",
            "action=edit",
            "/wiki/",
            "/wiki?",
            "/wikiword",
            "/wikisandbox",
            "/pmwiki",
            "cookbook",
            "/sitemap",
            "csdl/trans",
            "ieeexplore",
            "/petko",
            "/pmichaud",
            "wikivoyage",
            "en.wiktionary",
            "/indexdot",
            "home?action=login"
        ]):
            return False

       

        # filter for UCI domains only
        if not url.startswith("https://ics.uci.edu") and not url.startswith("https://www.ics.uci.edu"):
            return False
        

        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise
