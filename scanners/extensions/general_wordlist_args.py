from scanners.scanner import Scanner
from core.arg_registry import add_argument_once

@Scanner.register_args
def general_wordlists_args(parser, get_protocol_group):
    general_group = get_protocol_group(parser, "bruteforce")
    add_argument_once(general_group, "--general-userlist", nargs="+", help="General user wordlist(s) for all brute modules")
    add_argument_once(general_group, "--general-passlist", nargs="+", help="General password wordlist(s) for all brute modules")