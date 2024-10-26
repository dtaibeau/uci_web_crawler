from configparser import ConfigParser
from argparse import ArgumentParser
from utils.server_registration import get_cache_server
from utils.config import Config
from crawler import Crawler


def main(config_file, restart):
    cparser = ConfigParser()
    cparser.read(config_file)
    config = Config(cparser)
    config.cache_server = get_cache_server(config, restart)
    
    # make sure thread count is correct
    print(f"Starting crawler with {config.threads_count} threads")
    
    crawler = Crawler(config, restart)
    crawler.start()


if __name__ == "__main__":

    parser = ArgumentParser()
    parser.add_argument("--restart", action="store_true", default=False)
    parser.add_argument("--config_file", type=str, default="config.ini")
    args = parser.parse_args()
    main(args.config_file, args.restart)
