"""Blockchain investigation: wallet lookup, transaction graph, clustering and labels.

Reads only public blockchain explorers, through the allow-listing egress proxy,
exactly like enrichment: it asks an explorer *about* an address. It never holds
a private key, never signs and never broadcasts a transaction.
"""
