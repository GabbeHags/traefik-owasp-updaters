import datetime
from pathlib import Path
import shutil
import subprocess
import json
import logging
import tempfile
from typing import TypedDict

# Root logger
logger = logging.getLogger(Path(__file__).name)


# Constants
URL = "https://owasp.org/www-project-secure-headers/ci/headers_remove.json"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


class Curl:
    def __init__(self):
        pass

    def _execute(self, args: list[str]) -> str:
        cmd_output = subprocess.run(["curl", *args], capture_output=True)

        logger.debug(f"{cmd_output}")

        if cmd_output.returncode != 0:
            return ""

        return cmd_output.stdout.decode()

    def command_exists(self) -> bool:
        return not self.version().lstrip().startswith("curl")

    def version(self) -> str:
        return self._execute(["-V"])

    def get_data(self, url: str, args: list[str] = ["-s", "-f", "-L"]) -> str:
        # return self._execute([url, *args])
        return """{
  "last_update_utc": "2025-07-06 23:15:30",
  "headers": [
    "$wsep",
    "Host-Header",
    "K-Proxy-Request",
    "Liferay-Portal",
    "OracleCommerceCloud-Version",
    "Pega-Host",
    "Powered-By",
    "Product",
    "Server",
    "SourceMap",
    "X-AspNet-Version",
    "X-AspNetMvc-Version",
    "X-Atmosphere-error",
    "X-Atmosphere-first-request",
    "X-Atmosphere-tracking-id",
    "X-B3-ParentSpanId",
    "X-B3-Sampled",
    "X-B3-SpanId",
    "X-B3-TraceId",
    "X-BEServer",
    "X-Backside-Transport",
    "X-CF-Powered-By",
    "X-CMS",
    "X-CalculatedBETarget",
    "X-Cocoon-Version",
    "X-Content-Encoded-By",
    "X-DiagInfo",
    "X-Envoy-Attempt-Count",
    "X-Envoy-External-Address",
    "X-Envoy-Internal",
    "X-Envoy-Original-Dst-Host",
    "X-Envoy-Upstream-Service-Time",
    "X-FEServer",
    "X-Framework",
    "X-Generated-By",
    "X-Generator",
    "X-Jitsi-Release",
    "X-Joomla-Version",
    "X-Kubernetes-PF-FlowSchema-UI",
    "X-Kubernetes-PF-PriorityLevel-UID",
    "X-LiteSpeed-Cache",
    "X-LiteSpeed-Purge",
    "X-LiteSpeed-Tag",
    "X-LiteSpeed-Vary",
    "X-Litespeed-Cache-Control",
    "X-Mod-Pagespeed",
    "X-Nextjs-Cache",
    "X-Nextjs-Matched-Path",
    "X-Nextjs-Page",
    "X-Nextjs-Redirect",
    "X-OWA-Version",
    "X-Old-Content-Length",
    "X-OneAgent-JS-Injection",
    "X-Page-Speed",
    "X-Php-Version",
    "X-Powered-By",
    "X-Powered-By-Plesk",
    "X-Powered-CMS",
    "X-Redirect-By",
    "X-Server-Powered-By",
    "X-SourceFiles",
    "X-SourceMap",
    "X-Turbo-Charged-By",
    "X-Umbraco-Version",
    "X-Varnish-Backend",
    "X-Varnish-Server",
    "X-dtAgentId",
    "X-dtHealthCheck",
    "X-dtInjectedServlet",
    "X-ruxit-JS-Agent"
  ]
}"""


class _RemoveHeadersDict(TypedDict):
    last_update_utc: str | None
    headers: list[str] | None


class RemoveHeaders:
    def __init__(self, data_str: str):
        data: _RemoveHeadersDict = json.loads(data_str)

        # Validate the date
        if data["last_update_utc"] is None:
            raise ValueError('Could not find "last_update_utc"')
        self._last_update_utc = datetime.datetime.strptime(
            data["last_update_utc"], DATE_FORMAT
        )

        # Validate the headers
        if data["headers"] is None:
            raise ValueError('Could not find "headers"')
        self._headers = data["headers"]

        self._data = data

    @property
    def last_update_utc(self) -> datetime.datetime:
        return self._last_update_utc

    @property
    def headers(self) -> list[str]:
        return self._headers


def get_date_from_yaml_config(path: Path) -> datetime.datetime:
    # Default timestamp, if nothing is found
    last_update_utc = datetime.datetime.fromtimestamp(0)

    # Read yaml
    with open(path) as f:
        yaml_lines = f.readlines()

    # Try to find timestamp
    UPDATE_STRING = "# Updated on: "
    for line in yaml_lines:
        if line.startswith(UPDATE_STRING):
            # Timestamp found, trying to parse date
            try:
                last_update_utc = datetime.datetime.strptime(
                    line.removeprefix(UPDATE_STRING).strip(), DATE_FORMAT
                )
            except ValueError:
                logger.error("Could not parse last update timestamp")
            else:
                # Everything went well
                break
    else:
        logger.error(
            f"Could not find last update timestamp, will generate new from {URL}"
        )
    return last_update_utc


def write_yaml_config(path: Path, remove_headers: RemoveHeaders):
    ### As python does not have a yaml parser/writer in std, this will be best effort

    # Construct a 2d array where every row is a new indent and each column is
    # on the same indent
    string_2d = [
        [
            f"# DO NOT MODIFY. THIS FILE IS GENERATED FROM {URL}",
            # FIXME: This timedelta is just for testing, remove it
            f"# Updated on: {remove_headers.last_update_utc - datetime.timedelta(10)}",
            "http:",
        ],
        ["middlewares:"],
        ["owasp_headers_remove:"],
        ["headers:"],
        ["customResponseHeaders:"],
        [*[f'{headers_str}: ""' for headers_str in remove_headers.headers]],
    ]

    # Write headers to traefik config at `path`
    with open(path, "w") as f:
        indent_size = 2
        for tabs, strings_with_same_indent in enumerate(string_2d):
            for string in strings_with_same_indent:
                f.write(f"{' ' * indent_size * tabs}{string}\n")


def main() -> int:
    FILENAME = Path("middleware_owasp_headers_remove.yaml")

    curl = Curl()

    if curl.command_exists():
        logger.error('Could not find "curl"')
        return 1

    data = curl.get_data(URL)

    if data == "":
        logger.error(f"Something went wrong when getting data from url: {URL}")
        return 1

    # Get web version
    try:
        web_version = RemoveHeaders(data)
    except ValueError as err:
        logger.error(
            f"Something went wrong when validating data received from {URL}. Error: {err}"
        )
        return 1

    # Get local version
    if not FILENAME.exists():
        logger.warning(f"Could not find {FILENAME}, generating new file from {URL}")
    else:
        last_update_utc = get_date_from_yaml_config(FILENAME)

        # Check if our file is newer or equal to the web version
        if last_update_utc >= web_version.last_update_utc:
            logger.info("We are already up to date. Exiting...")
            return 0

        # Our file was not up to date, save and update local headers
        logger.info("Found newer version, starting to update local version of headers")

    # Save old yaml config to be able to go back to if the updated version generates errors
    tmp_dir = tempfile.TemporaryDirectory()
    shutil.copy2(FILENAME, tmp_dir.name)
    old_file = Path(tmp_dir.name) / FILENAME.name

    # Have a big try except to catch if something goes wrong when updating file
    try:
        # Write headers to traefik config: middleware_owasp_headers_remove.yaml
        write_yaml_config(FILENAME, web_version)

        # restart traefik to see if the change generated errors
        ### If the change generates errors we go back to the old version
        # TODO

    except Exception as err:
        # Remove the newly written yaml config

        # Move back the old file
        pass
    tmp_dir.cleanup()

    return 0


def setup_logging():
    # logging.basicConfig(filename="myapp.log", level=logging.INFO)
    log_formatter = logging.Formatter(
        "%(asctime)s [%(levelname)-4.7s] %(filename)s:%(lineno)d  %(message)s"
    )
    fileHandler = logging.FileHandler(f"{Path(__file__).name}.log")

    fileHandler.setFormatter(log_formatter)
    logger.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(log_formatter)
    logger.addHandler(consoleHandler)
    logger.setLevel(logging.INFO)


if __name__ == "__main__":
    setup_logging()

    # Handle cli
    ### Generate config, which we give to main
    # TODO

    exit(main())
