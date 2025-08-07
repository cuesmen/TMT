
def print_info(message):
    print(f"\N{Large Green Circle} {message}")

def print_warn(message):
    print(f"\N{Large Orange Circle} {message}")

def err_exit(message):
    print(f"\N{Large Red Circle} {message}")
    exit(-1)