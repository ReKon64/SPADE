_registered_args = set()

def add_argument_once(group, *args, **kwargs):
    # Only add if none of the option strings are already registered
    for arg in args:
        if arg in _registered_args:
            return
    group.add_argument(*args, **kwargs)
    for arg in args:
        _registered_args.add(arg)