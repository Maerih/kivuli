"""Entity recognition: threat actors, malware families and organisations.

Matching is gazetteer-based: the pipeline hands in the entities it knows (curated
seeds, groups reported by trackers, victims, analyst-created records) and gets
back the ones a document mentions. A conservative pattern pass also proposes
organisation names that are not known yet.
"""
import re
from dataclasses import dataclass

# (name, aliases). Names that are ordinary words are only matched next to
# ransomware/group context - see _needs_context.
CURATED_ACTORS: list[tuple[str, list[str]]] = [
    ("LockBit", ["LockBit 3.0", "LockBit Black", "LockBit Green", "lockbit3", "lockbit5"]),
    ("ALPHV", ["BlackCat", "ALPHV/BlackCat", "Noberus"]),
    ("Cl0p", ["Clop", "TA505"]),
    ("Akira", []),
    ("Play", ["PlayCrypt"]),
    ("Black Basta", ["BlackBasta"]),
    ("Medusa", ["MedusaLocker", "Medusa Blog"]),
    ("RansomHub", []),
    ("Qilin", ["Agenda"]),
    ("8Base", []),
    ("BianLian", []),
    ("Rhysida", []),
    ("Hunters International", ["Hunters"]),
    ("INC Ransom", ["INC Ransomware", "incransom"]),
    ("DragonForce", []),
    ("Cactus", []),
    ("BlackSuit", ["Royal"]),
    ("Conti", []),
    ("REvil", ["Sodinokibi"]),
    ("Hive", []),
    ("Vice Society", []),
    ("LAPSUS$", ["Lapsus"]),
    ("Scattered Spider", ["UNC3944", "Octo Tempest", "0ktapus"]),
    ("ShinyHunters", []),
    ("IntelBroker", []),
    ("KillNet", []),
    ("Anonymous Sudan", []),
    ("NoName057(16)", ["NoName057"]),
    ("Funksec", []),
    ("Lynx", []),
    ("SafePay", []),
    ("Everest", []),
    ("Stormous", []),
    ("Mallox", ["TargetCompany"]),
    ("Snatch", []),
    ("Ragnar Locker", ["RagnarLocker"]),
    ("Babuk", []),
    ("Monti", []),
    ("Trigona", []),
    ("KillSec", ["Kill Security"]),
    ("RansomEXX", []),
    ("Arcus Media", []),
    ("Space Bears", ["SpaceBears"]),
    ("Embargo", []),
    ("Fog", []),
    ("Interlock", []),
    ("Sarcoma", []),
    ("Termite", []),
    ("APT28", ["Fancy Bear", "Sofacy", "Forest Blizzard"]),
    ("APT29", ["Cozy Bear", "Midnight Blizzard", "NOBELIUM"]),
    ("Lazarus Group", ["Lazarus", "Hidden Cobra", "APT38"]),
    ("Kimsuky", ["APT43"]),
    ("Sandworm", ["APT44", "Seashell Blizzard"]),
    ("Volt Typhoon", []),
    ("Salt Typhoon", []),
    ("APT41", ["Winnti", "Double Dragon"]),
    ("MuddyWater", ["Mango Sandstorm"]),
    ("Charming Kitten", ["APT35", "Mint Sandstorm"]),
    ("FIN7", ["Carbanak"]),
    ("SilverTerrier", []),
]

CURATED_MALWARE: list[tuple[str, list[str]]] = [
    ("Emotet", []), ("QakBot", ["Qbot", "QuakBot"]), ("TrickBot", []), ("IcedID", ["BokBot"]),
    ("RedLine", ["RedLine Stealer"]), ("Raccoon Stealer", ["Raccoon"]), ("Vidar", []), ("Lumma", ["LummaC2", "Lumma Stealer"]),
    ("StealC", []), ("Agent Tesla", ["AgentTesla"]), ("FormBook", ["XLoader"]), ("AsyncRAT", []), ("Remcos", ["RemcosRAT"]),
    ("Cobalt Strike", ["CobaltStrike"]), ("Mimikatz", []), ("SystemBC", []), ("Mirai", []), ("Sliver", []),
    ("njRAT", []), ("DarkGate", []), ("PikaBot", []), ("SocGholish", ["FakeUpdates"]), ("BumbleBee", []),
    ("Meduza Stealer", []), ("RisePro", []), ("Atomic Stealer", ["AMOS"]), ("Pegasus", []), ("Predator", []),
]

# Ordinary words that happen to be actor or malware names.
_COMMON_WORDS = {
    "play", "cuba", "royal", "medusa", "hive", "knight", "lynx", "everest", "cactus", "monti", "snatch", "embargo",
    "fog", "abyss", "trinity", "cloak", "meow", "eldorado", "termite", "orca", "nitrogen", "interlock", "kraken",
    "sarcoma", "hunters", "agenda", "raccoon", "predator", "pegasus", "sliver", "mirai", "lumma", "conti", "akira",
    "space", "money", "black", "apos", "qilin", "team", "leak", "data", "world", "global", "lazarus", "sandworm",
    "inc", "arcus", "helldown", "chaos", "nova", "rabbit", "blacksuit", "stormous", "crypto", "silent", "morpheus",
    "rhysida", "dispossessor", "flocker", "brain", "weyhro", "linkc", "anubis", "gunra", "devman", "warlock",
}
_CONTEXT = re.compile(
    r"\b(?:ransomware|ransom|gang|group|locker|leak|leaks|team|operators?|affiliates?|actors?|claimed|claims|listed|"
    r"stealer|malware|trojan|botnet|rat|apt|hackers?|campaign|blog|extortion|victims?)\b",
    re.I,
)
_TOKEN = re.compile(r"[a-z0-9$]+(?:\([0-9]+\))?")


def _tokens(text: str) -> list[str]:
    return _TOKEN.findall(text.lower())


def needs_context(name: str, curated: bool) -> bool:
    """True when a bare mention of ``name`` is too weak to count on its own."""
    tokens = _tokens(name)
    if not tokens:
        return True
    if len(tokens) == 1:
        token = tokens[0]
        if token in _COMMON_WORDS or len(token) <= 4:
            return True
        # Tracker-reported names are unvetted; single plain words need support.
        return not curated and token.isalpha() and len(token) <= 9
    return all(t in _COMMON_WORDS for t in tokens)


def distinctive(name: str) -> bool:
    """True when a name is unlikely to be an ordinary word: it has a digit, an
    inner capital, punctuation or several words (APT28, TrickBot, Sandworm Team)."""
    if len(name.split()) > 1:
        return True
    return bool(re.search(r"\d|[^\w]|[a-z][A-Z]|[A-Z]{2}[a-z]", name)) or (name.isupper() and len(name) >= 6)


@dataclass(frozen=True)
class KnownEntity:
    id: int
    type: str
    name: str
    aliases: tuple[str, ...] = ()
    curated: bool = False
    # Imported reference names (ATT&CK): any that could be an ordinary word needs context.
    contextual: bool = False


class EntityMatcher:
    """Phrase matcher keyed on the first token of each known name."""

    def __init__(self, entities: list[KnownEntity]):
        self._index: dict[str, list[tuple[tuple[str, ...], KnownEntity, bool]]] = {}
        self.size = len(entities)
        for entity in entities:
            for name in (entity.name, *entity.aliases):
                tokens = tuple(_tokens(name))
                if not tokens or (entity.type == "organization" and len(name) < 5):
                    continue
                if len(tokens) == 1 and len(tokens[0]) < 3:
                    continue
                context = needs_context(name, entity.curated) or (entity.contextual and not distinctive(name))
                self._index.setdefault(tokens[0], []).append((tokens, entity, context))

    def find(self, text: str) -> dict[int, int]:
        """Return {entity id: mention count} for entities mentioned in ``text``."""
        lowered = text[:300_000].lower()
        positions = [(m.group(0), m.start()) for m in _TOKEN.finditer(lowered)]
        tokens = [t for t, _ in positions]
        found: dict[int, int] = {}
        for i, token in enumerate(tokens):
            for phrase, entity, contextual in self._index.get(token, ()):
                if tuple(tokens[i : i + len(phrase)]) != phrase:
                    continue
                if contextual:
                    start = positions[i][1]
                    window = lowered[max(0, start - 60) : start + 90]
                    if not _CONTEXT.search(window.replace(" ".join(phrase), " ")):
                        continue
                found[entity.id] = found.get(entity.id, 0) + 1
        return found


_ORG_SUFFIX = (
    r"Ltd|Limited|Inc|LLC|PLC|Plc|Corp|Corporation|GmbH|S\.A\.|SA|AG|Pty|Bank|Sacco|SACCO|University|College|Hospital|"
    r"Hospitals|Clinic|Authority|Commission|Ministry|Insurance|Assurance|Telecom|Telkom|Airways|Airlines|Holdings|"
    r"Group|Industries|Technologies|Systems|Solutions|Pharmaceuticals|Logistics|Energy|Brokers|Partners|Associates"
)
_CAP = r"[A-Z][\w&'-]*"
RE_ORG_SUFFIXED = re.compile(rf"\b((?:{_CAP}\s+){{1,4}}(?:{_ORG_SUFFIX}))(?![\w-])")
RE_ORG_PREFIXED = re.compile(
    rf"\b((?:Ministry|Bank|University|Government|County Government|Department|Republic|State Department) of (?:the )?(?:{_CAP})(?:\s+{_CAP}){{0,3}})"
)
_ORG_STOP = {"The Group", "The Bank", "This Group", "Our Group", "The University", "The Ministry", "The Authority", "The Commission"}


def propose_organizations(text: str, limit: int = 12) -> list[str]:
    """Organisation names recognisable by form alone (Acme Holdings, Ministry of X)."""
    seen: dict[str, int] = {}
    for pattern in (RE_ORG_SUFFIXED, RE_ORG_PREFIXED):
        for match in pattern.finditer(text[:120_000]):
            name = " ".join(match.group(1).split()).strip(" .,")
            name = re.sub(r"^(?:The|A|An|And|At|In|On|By|From|For|With|Of)\s+", "", name)
            if len(name) < 6 or len(name) > 80 or name in _ORG_STOP or len(name.split()) < 2:
                continue
            seen[name] = seen.get(name, 0) + 1
    return [name for name, _ in sorted(seen.items(), key=lambda kv: kv[1], reverse=True)[:limit]]
