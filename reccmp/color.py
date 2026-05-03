import os
import colorama

COLOR_ENABLED = not os.environ.get("NO_COLOR")


class Fore:
    RED = colorama.Fore.RED if COLOR_ENABLED else ""
    GREEN = colorama.Fore.GREEN if COLOR_ENABLED else ""
    BLUE = colorama.Fore.BLUE if COLOR_ENABLED else ""
    YELLOW = colorama.Fore.YELLOW if COLOR_ENABLED else ""
    WHITE = colorama.Fore.WHITE if COLOR_ENABLED else ""
    LIGHTWHITE_EX = colorama.Fore.LIGHTWHITE_EX if COLOR_ENABLED else ""
    LIGHTBLACK_EX = colorama.Fore.LIGHTBLACK_EX if COLOR_ENABLED else ""


class Style:
    RESET_ALL = colorama.Style.RESET_ALL if COLOR_ENABLED else ""
