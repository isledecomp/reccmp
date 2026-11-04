import textwrap

RECCMP_PROJECT_CONFIG = "reccmp-project.yml"
RECCMP_USER_CONFIG = "reccmp-user.yml"
RECCMP_BUILD_CONFIG = "reccmp-build.yml"


def helper_create_project(target_name: str, filename: str, sha256: str) -> str:
    """Creates YML for a project file with one target using the given parameters."""
    return textwrap.dedent(f"""\
        targets:
          {target_name}:
            filename: {filename}
            source-root: sources
            hash:
              sha256: {sha256}
    """)
