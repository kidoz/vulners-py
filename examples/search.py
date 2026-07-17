"""Search Vulners and print bulletin identifiers."""

from _env import load_dotenv

from vulners import Vulners

load_dotenv()

with Vulners() as client:
    for bulletin in client.search.bulletins_iter("wordpress", limit=100):
        print(bulletin.id)
