import os
import colorama


class Fore:
    RED = ""
    GREEN = ""
    BLUE = ""
    YELLOW = ""
    WHITE = ""
    LIGHTWHITE_EX = ""
    LIGHTBLACK_EX = ""


class Style:
    RESET_ALL = ""


def setup_colorama():
    Fore.RED = colorama.Fore.RED
    Fore.GREEN = colorama.Fore.GREEN
    Fore.BLUE = colorama.Fore.BLUE
    Fore.YELLOW = colorama.Fore.YELLOW
    Fore.WHITE = colorama.Fore.WHITE
    Fore.LIGHTWHITE_EX = colorama.Fore.LIGHTWHITE_EX
    Fore.LIGHTBLACK_EX = colorama.Fore.LIGHTBLACK_EX

    Style.RESET_ALL = colorama.Style.RESET_ALL


def setup_plain():
    Fore.RED = ""
    Fore.GREEN = ""
    Fore.BLUE = ""
    Fore.YELLOW = ""
    Fore.WHITE = ""
    Fore.LIGHTWHITE_EX = ""
    Fore.LIGHTBLACK_EX = ""

    Style.RESET_ALL = ""


def enable_color(enable: bool) -> None:
    if enable and not os.environ.get("NO_COLOR"):
        setup_colorama()
    else:
        setup_plain()


enable_color(True)
