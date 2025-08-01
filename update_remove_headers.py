import datetime
import os
from pathlib import Path
import shutil
import subprocess
import json
import logging
import tempfile
import time
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
        return self._execute([url, *args])


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
    logger.debug(f"Timestamp found in yaml: {last_update_utc}")
    return last_update_utc


def write_yaml_config(path: Path, middleware_name: str, remove_headers: RemoveHeaders):
    ### As python does not have a yaml parser/writer in std, this will be best effort

    # Construct a 2d array where every row is a new indent and each column is
    # on the same indent
    string_2d = [
        [
            f"# DO NOT MODIFY. THIS FILE IS GENERATED FROM {URL}",
            f"# Updated on: {remove_headers.last_update_utc}",
            "http:",
        ],
        ["middlewares:"],
        [f"{middleware_name}:"],
        ["headers:"],
        ["customResponseHeaders:"],
        [*[f'{headers_str}: ""' for headers_str in remove_headers.headers]],
    ]

    with open(path, "w") as f:
        indent_size = 2
        for tabs, strings_with_same_indent in enumerate(string_2d):
            for string in strings_with_same_indent:
                f.write(f"{' ' * indent_size * tabs}{string}\n")


def main(config: "Config") -> int:
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
    tmp_dir: tempfile.TemporaryDirectory | None
    old_file: Path | None
    if config.config_path.exists():
        tmp_dir = tempfile.TemporaryDirectory()
        last_update_utc = get_date_from_yaml_config(config.config_path)

        # Check if our file is newer or equal to the web version
        if last_update_utc >= web_version.last_update_utc:
            logger.info("We are already up to date. Exiting...")
            return 0

        # Our file was not up to date, save and update local headers
        logger.info("Found newer version, starting to update local version of headers")

        # Save old yaml config to be able to go back to if the updated version generates errors
        logger.info("Making backup of current version")
        shutil.copy2(config.config_path, tmp_dir.name)
        old_file = Path(tmp_dir.name) / config.config_path.name
    else:
        tmp_dir = None
        old_file = None
        logger.warning(
            f"Could not find {config.config_path}, generating new file from {URL}"
        )

    # Have a big try except to catch if something goes wrong when updating file
    try:
        logger.debug(f"Write headers to traefik config at `{config.config_path}`")
        if config.traefik_log is not None:
            # save timestamp so we know where we need to start the search from
            timestamp_before_writing = datetime.datetime.now().astimezone()

        write_yaml_config(
            config.config_path,
            config.middleware_header,
            web_version,
        )

        if config.restart_traefik:
            logger.info("Restarting Traefik to apply changes")
            traefik_restart_proc = subprocess.run(config.traefik_restart_cmd.split())
            traefik_restart_proc.check_returncode()
            logger.debug("traefik restart with 0 as exit code")

        # If the change generates errors we go back to the old version
        if config.traefik_log is not None:
            logger.info(
                f"Reading traefik logs for {config.wait_for_errors_time} seconds at: {config.traefik_log}"
            )
            end_time = time.time() + config.wait_for_errors_time
            with open(config.traefik_log) as f:
                log_msg = ""
                while time.time() <= end_time or config.wait_for_errors_time == 0:
                    for line in f:
                        try:
                            timestamp = datetime.datetime.fromisoformat(
                                line.split()[0].strip()
                            )
                            log_msg = line
                        except Exception:
                            # If we get here we know that we are still on the same log message
                            # So we append it do the log_msg string
                            log_msg += f"\n{line}"
                            continue
                        if (
                            timestamp_before_writing
                            <= timestamp  # Timestamp is after writing the file
                            and "ERR" in log_msg  # There is an error
                            and (
                                config.middleware_header in log_msg
                                or config.config_path.name in log_msg
                            )  # The error contain our header or file
                        ):
                            raise RuntimeError(
                                f"Found errors in {config.traefik_log} that could be caused by the update"
                            )
                    if config.wait_for_errors_time == 0:
                        # the wait time is zero, so we will just run through lines ones.
                        break
            logger.info(
                f"Found no errors in log, related to {config.middleware_header} or {config.config_path}"
            )

    except Exception as err:
        logger.error(
            f"Something went wrong when updating, reverting changes. Error: {err}"
        )
        # Remove the newly written yaml config
        if config.config_path.exists():
            os.remove(config.config_path)

        # Move back the old file
        if tmp_dir is not None and old_file is not None and old_file.exists():
            shutil.copy2(old_file, config.config_path)
            if config.restart_traefik:
                logger.info("Restarting Traefik to revert changes")
                traefik_restart_proc = subprocess.run(
                    config.traefik_restart_cmd.split()
                )

    if tmp_dir is not None:
        tmp_dir.cleanup()

    logger.info("Update was successful")
    return 0


def setup_logging(config: "Config"):
    log_formatter = logging.Formatter(
        "%(asctime)s [%(levelname)-4.7s] %(filename)s:%(lineno)d  %(message)s"
    )

    if config.log_path is not None:
        fileHandler = logging.FileHandler(config.log_path)
        fileHandler.setFormatter(log_formatter)
        logger.addHandler(fileHandler)

    consoleHandler = logging.StreamHandler()
    consoleHandler.setFormatter(log_formatter)
    logger.addHandler(consoleHandler)
    logger.setLevel(config.log_level)


class Config:
    def __init__(
        self,
        *,
        config_path: str,
        middleware_header: str,
        restart_traefik: bool,
        traefik_restart_cmd: str,
        wait_for_errors_time: str,
        log_level: str,
        log_path: str | None,
        traefik_log: str | None,
    ):
        if not wait_for_errors_time.isdigit():
            raise ValueError(
                "The given wait for errors time is not a valid digit/number"
            )
        self._wait_for_errors_time = int(wait_for_errors_time)

        tmp_config_path = Path(config_path).resolve()
        if not tmp_config_path.parent.exists():
            raise ValueError(f"The given config path does not exist. {tmp_config_path}")
        if not tmp_config_path.suffix.endswith(("yaml", "yml")):
            raise ValueError(
                "The given config file is expected to have the extension yml or yaml"
            )
        self._config_path = tmp_config_path

        self._restart_traefik = restart_traefik

        if middleware_header.strip() == "":
            raise ValueError(f'The given middleware "{middleware_header}" is not valid')
        else:
            self._middleware_header = middleware_header

        if traefik_restart_cmd.strip() == "":
            raise ValueError(
                f"The given restart command is empty. Command: {traefik_restart_cmd}"
            )
        else:
            self._traefik_restart_cmd = traefik_restart_cmd

        tmp_log_level = logging.getLevelNamesMapping().get(log_level.upper())
        if tmp_log_level is None:
            raise ValueError(
                f'The given log level "{log_level}" is not a valid debug level. Valid levels: {list(logging.getLevelNamesMapping().keys())}'
            )
        self._log_level = tmp_log_level

        if log_path is not None:
            tmp_log_path = Path(log_path).resolve()
            print(tmp_log_path.is_file())
            if not tmp_log_path.parent.exists():
                raise ValueError(
                    f'The given "log_path" does not exist. The directory "{tmp_log_path.parent}" is expected to exist'
                )

            self._log_path = tmp_log_path
        else:
            self._log_path = None

        if traefik_log is not None:
            tmp_traefik_log = Path(traefik_log).resolve()
            if not tmp_traefik_log.parent.exists() or not tmp_traefik_log.is_file():
                raise ValueError(
                    f"The given traefik_log path does not exist. {tmp_traefik_log}"
                )
            self._traefik_log = tmp_traefik_log
        else:
            self._traefik_log = None

    @property
    def log_level(self) -> int:
        return self._log_level

    @property
    def log_path(self) -> Path | None:
        return self._log_path

    @property
    def config_path(self) -> Path:
        return self._config_path

    @property
    def middleware_header(self) -> str:
        return self._middleware_header

    @property
    def traefik_log(self) -> Path | None:
        return self._traefik_log

    @property
    def restart_traefik(self) -> bool:
        return self._restart_traefik

    @property
    def traefik_restart_cmd(self) -> str:
        return self._traefik_restart_cmd

    @property
    def wait_for_errors_time(self) -> int:
        return self._wait_for_errors_time


def cli() -> Config:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-c",
        "--config-path",
        required=True,
        help="Path to where the generated config will be stored",
    )
    DEFAULT_MIDDLEWARE_HEADER = "owasp_headers_remove"
    parser.add_argument(
        "--middleware-header",
        default=DEFAULT_MIDDLEWARE_HEADER,
        help=f"The name of the middleware header. Default {DEFAULT_MIDDLEWARE_HEADER}",
    )
    DEFAULT_LOG_LEVEL = "INFO"
    parser.add_argument(
        "--log-level",
        default=DEFAULT_LOG_LEVEL,
        help=f"The log level. Default {DEFAULT_LOG_LEVEL}",
    )
    parser.add_argument(
        "--log-path",
        help="Path to log file. If not set no log file will be created",
    )
    parser.add_argument(
        "--traefik-log",
        help="The path to the log file for Traefik. This is used to check if the update generated any errors.",
    )
    DEFAULT_WAIT_FOR_ERRORS_TIME = "5"
    parser.add_argument(
        "--wait-for-errors-time",
        default=DEFAULT_WAIT_FOR_ERRORS_TIME,
        help=f"The wait time to wait for errors in the traefik log. Default {DEFAULT_WAIT_FOR_ERRORS_TIME}",
    )
    DEFAULT_RESTART_CMD = "systemctl restart traefik.service"
    parser.add_argument(
        "--traefik-restart-cmd",
        default=DEFAULT_RESTART_CMD,
        help=f'The command that will be used when restarting traefik. This is only used when "--restart-traefik" is given. Default {DEFAULT_RESTART_CMD}',
    )
    parser.add_argument(
        "-r",
        "--restart-traefik",
        action="store_false",
        help=f'Restart traefik with by default the command: "{DEFAULT_RESTART_CMD}" to apply changes. This can be changed with "--traefik-restart-cmd"',
    )

    args = parser.parse_args()

    return Config(
        config_path=args.config_path,
        middleware_header=args.middleware_header,
        restart_traefik=args.restart_traefik,
        wait_for_errors_time=args.wait_for_errors_time,
        traefik_restart_cmd=args.traefik_restart_cmd,
        log_level=args.log_level,
        log_path=args.log_path,
        traefik_log=args.traefik_log,
    )


if __name__ == "__main__":
    import argparse

    # Handle cli
    config = cli()

    # Setup logging
    setup_logging(config)

    return_code = 1
    try:
        return_code = main(config)
    except Exception as err:
        logger.error(f"Got an error while running script. Error: {err}")

    exit(return_code)
