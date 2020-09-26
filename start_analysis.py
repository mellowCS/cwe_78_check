#!/usr/bin/python3

from pathlib import Path
import subprocess
import argparse

PLUGINS = 'plugins'

def start_analysis(command: list):
    try:
        subprocess.run(args=command, stderr=subprocess.STDOUT, cwd=str(Path.cwd()))
    except subprocess.CalledProcessError as err:
        print('Status : FAIL', err.returncode)


def build_command(ghidra: Path, import_: Path) -> list:
    ghidra = ghidra / 'support' / 'analyzeHeadless'
    project_root = Path.cwd()
    tmp = project_root / 'tmp'
    if not tmp.is_dir():
        tmp.mkdir()
    command = [str(ghidra), str(tmp), 'PcodeExtractor', '-import', str(import_), '-postScript', 'OsComInjection.java', str(tmp / (import_.name + '.json')),  '-scriptPath', str(project_root), '-deleteProject']

    return command


def plugin_folder_exists(path: Path):
    plugin_path = path / PLUGINS
    if not plugin_path.is_dir():
        plugin_path.mkdir()

def is_in_classpath(location: Path, filename: str) -> bool:
    plugin_path = location / PLUGINS
    if list(plugin_path.glob('gson*.jar')):
        return True
    return False


def is_directory(parser: argparse.ArgumentParser, path: str) -> Path:
    dir = Path(path)
    if dir.is_dir() and 'ghidra' in path:
        return dir
    parser.error(f'Given Ghidra path {path} is not valid.')


def is_file(parser: argparse.ArgumentParser, path: str) -> Path:
    file = Path(path)
    if file.is_file():
        return file
    parser.error(f'Binary could not be found at {path}.')


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('-g', '--ghidra', required=True, dest='ghidra', help='Path to Ghidra. Ends in .../ghidra_9.X.X_PUBLIC/.',
    metavar='PATH', type=lambda d: is_directory(parser, d))

    parser.add_argument('-i', '--import', required=True, dest='import_', help='Path to binary which is to be analysed by Ghidra.',
    metavar='FILE', type=lambda f: is_file(parser, f))

    args = parser.parse_args()

    return args


def main():
    args = parse_args()
    command = build_command(args.ghidra, args.import_)
    start_analysis(command=command)


if __name__ == '__main__':
    main()
