"""Auto-paginate a Vulners bulletin search and print every identifier."""

from _env import load_dotenv

from vulners import Vulners

load_dotenv()

with Vulners() as client:
    for bulletin in client.search.iter_bulletins("wordpress", limit=100):
        print(bulletin.id)
