"""Search Vulners and print bulletin identifiers."""

from vulners import Vulners

with Vulners() as client:
    for bulletin in client.search.bulletins_iter("wordpress", limit=100):
        print(bulletin.id)
