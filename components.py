#!/usr/bin/env python3
"""Builds the unsigned payload of the desktop app's component manifest (docs/desktop-app.md, design point 8).

Runs every 6 hours in the public release repository's CI. Every upstream file is checked before it is listed. Claude
Code is checked against Anthropic's GPG-signed release manifest and npm's integrity strings, and a mirror is
listed only when it serves the byte-identical package. CC Switch files are downloaded once from GitHub and must
match the release's asset digest. Claude Desktop is hashed here from Anthropic's own download host, which publishes
no installer checksums. A platform that fails any check is left out. A bad
release-manifest signature fails the whole run, so the previous signed manifest stays published.

The payload is then signed by `sign-manifest` (desktop/core/src/bin), which refuses anything the app would.
Usage: components.py <payload.json>
"""
import base64
import collections
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

SCHEMA = 'vps-desktop-components-v1'
LIFETIME = 7 * 86400
PLATFORMS = ('darwin-arm64', 'darwin-x64', 'linux-x64', 'linux-arm64',
             'linux-x64-musl', 'linux-arm64-musl', 'win32-x64', 'win32-arm64')
RELEASES = 'https://downloads.claude.ai/claude-code-releases'
KEY_URL = 'https://downloads.claude.ai/keys/claude-code.asc'
FINGERPRINT = '31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE'
ORIGIN = 'https://registry.npmjs.org'
# The app tries sources in this order: mirrors reachable from China first, the origin last.
MIRRORS = ('https://registry.npmmirror.com', 'https://mirrors.cloud.tencent.com/npm',
           'https://repo.huaweicloud.com/repository/npm')
PACKAGE = '@anthropic-ai/claude-code-{platform}'
VERSION = re.compile(r'[0-9A-Za-z.+-]{1,64}')
SHA256 = re.compile(r'[0-9a-f]{64}')
MAX_DOWNLOAD = 2 << 30
CC_SWITCH_API = 'https://api.github.com/repos/farion1231/cc-switch/releases/latest'
CC_SWITCH_DOWNLOAD = 'https://github.com/farion1231/cc-switch/releases/download/'
# Platform -> (release asset, installer format). Both Macs share the one dmg: the release's updater manifest
# maps darwin-aarch64 and darwin-x86_64 to the same macOS bundle (v4.0.33, checked 2026-11-16). Linux takes
# the deb, like Claude Desktop: the AppImage runtime needs libfuse2, which Ubuntu no longer installs by default.
CC_SWITCH_ASSETS = {
    'darwin-arm64': ('CC-Switch-v{version}-macOS.dmg', 'dmg'),
    'darwin-x64': ('CC-Switch-v{version}-macOS.dmg', 'dmg'),
    'linux-x64': ('CC-Switch-v{version}-Linux-x86_64.deb', 'deb'),
    'linux-arm64': ('CC-Switch-v{version}-Linux-arm64.deb', 'deb'),
    'win32-x64': ('CC-Switch-v{version}-Windows.msi', 'msi'),
    'win32-arm64': ('CC-Switch-v{version}-Windows-arm64.msi', 'msi'),
}
# Third-party GitHub download proxies, tried before github.com. The app checks every byte against the signed
# manifest, so a proxy can only be slow or wrong, never trusted. Order from one measurement in China on
# 2026-11-16 (docs/desktop-app.md, CI manifest generator record).
GITHUB_PROXIES = ('https://gh-proxy.org/', 'https://ghfast.top/', 'https://gh-proxy.com/')
DESKTOP_REDIRECT = 'https://api.anthropic.com/api/desktop/{path}/latest/redirect'
# Platform -> (redirect path, installer format). Both Macs share the universal dmg.
DESKTOP_ASSETS = {
    'darwin-arm64': ('darwin/universal/dmg', 'dmg'),
    'darwin-x64': ('darwin/universal/dmg', 'dmg'),
    'linux-x64': ('linux/x64/deb', 'deb'),
    'linux-arm64': ('linux/arm64/deb', 'deb'),
    'win32-x64': ('win32/x64/msix', 'msix'),
    'win32-arm64': ('win32/arm64/msix', 'msix'),
}
DESKTOP_FILE = re.compile(r'https://downloads\.claude\.ai/releases/(?P<target>[a-z0-9]+/[a-z0-9]+)/'
                          r'(?P<version>[0-9A-Za-z.+-]{1,64})/Claude-[0-9a-f]{40}\.(?P<ext>[a-z]+)')


class Refused(Exception):
    """An upstream check failed; the message says which."""


def fetch(url, limit=MAX_DOWNLOAD):
    headers = {'user-agent': 'vps-desktop-manifest'}
    token = os.environ.get('GITHUB_TOKEN')
    if token and url.startswith('https://api.github.com/'):
        # The Actions token avoids the shared runners' anonymous API rate limit.
        headers['authorization'] = f'Bearer {token}'
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            body = response.read(limit + 1)
    except http.client.HTTPException as error:
        # A connection cut mid-body (IncompleteRead) costs one platform, not the run.
        raise Refused(f'{url}: {type(error).__name__}') from None
    if len(body) > limit:
        raise Refused(f'{url}: larger than {limit} bytes')
    return body


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def resolve(url):
    """The address a redirect points to, without following it."""
    opener = urllib.request.build_opener(NoRedirect)
    request = urllib.request.Request(url, headers={'user-agent': 'vps-desktop-manifest'})
    try:
        with opener.open(request, timeout=60):
            pass
    except urllib.error.HTTPError as error:
        location = error.headers.get('location')
        if error.code in (301, 302, 303, 307, 308) and location:
            return location
        raise
    raise Refused(f'{url}: answered without a redirect')


def usable(url):
    """The source rules the app enforces (manifest.rs check_sources)."""
    return (isinstance(url, str) and url.startswith('https://') and len(url) <= 2048
            and not any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url))


def gpg_verify(manifest, signature, key, run=subprocess.run):
    """True only for a good signature over `manifest` by the release key, checked by fingerprint in an empty keyring."""
    with tempfile.TemporaryDirectory() as home:
        base = ['gpg', '--batch', '--no-tty', '--homedir', home]
        run(base + ['--import'], input=key, capture_output=True, check=True)
        data, sig = Path(home)/'manifest.json', Path(home)/'manifest.json.sig'
        data.write_bytes(manifest)
        sig.write_bytes(signature)
        result = run(base + ['--status-fd', '1', '--verify', str(sig), str(data)], capture_output=True)
    if result.returncode != 0:
        return False
    for line in result.stdout.decode(errors='replace').splitlines():
        fields = line.split()
        # VALIDSIG <signing-key fingerprint> ... <primary-key fingerprint>
        if len(fields) > 2 and fields[:2] == ['[GNUPG:]', 'VALIDSIG'] and FINGERPRINT in (fields[2], fields[-1]):
            return True
    return False


def locate(tgz, checksum, size=None):
    """The path and size of the one regular file whose SHA-256 is `checksum`; no other entry may share its path."""
    names, found = [], []
    with tarfile.open(fileobj=io.BytesIO(tgz), mode='r:gz') as archive:
        for member in archive:
            names.append(member.name)
            if member.isreg():
                data = archive.extractfile(member).read()
                if hashlib.sha256(data).hexdigest() == checksum:
                    found.append((member.name, len(data)))
    if len(found) != 1:
        raise Refused(f'{len(found)} files match the official checksum')
    name, length = found[0]
    parts = name.split('/')
    if (names.count(name) != 1 or name.startswith('/') or '\\' in name or len(name) > 256
            or any(part in ('', '.', '..') for part in parts)):
        raise Refused(f'unusable entry path {name!r}')
    if size is not None and size != length:
        raise Refused('binary size differs from the official manifest')
    return name, length


def npm_dist(registry, platform, version, fetch):
    name = PACKAGE.format(platform=platform).replace('/', '%2f')
    dist = json.loads(fetch(f'{registry}/{name}/{version}', 4 << 20))['dist']
    if not isinstance(dist, dict):
        raise Refused('dist is not an object')
    return dist


def npm_artifact(platform, version, official, fetch):
    checksum, size = official['checksum'], official.get('size')
    if not isinstance(checksum, str) or not SHA256.fullmatch(checksum):
        raise Refused('official checksum is malformed')
    if size is not None and (type(size) is not int or size <= 0):
        raise Refused('official size is malformed')
    dist = npm_dist(ORIGIN, platform, version, fetch)
    integrity, tarball = dist.get('integrity'), dist.get('tarball')
    if not isinstance(integrity, str) or not usable(tarball):
        raise Refused('origin metadata is malformed')
    tgz = fetch(tarball)
    if integrity != 'sha512-' + base64.b64encode(hashlib.sha512(tgz).digest()).decode():
        raise Refused('origin tarball does not match its integrity')
    entry, binary_size = locate(tgz, checksum, size)
    sources = []
    for registry in MIRRORS:
        try:
            mirror = npm_dist(registry, platform, version, fetch)
        except (OSError, ValueError, KeyError, TypeError, Refused):
            continue
        url = mirror.get('tarball')
        if mirror.get('integrity') == integrity and usable(url) and url not in sources and url != tarball:
            sources.append(url)
    sources.append(tarball)
    return {'kind': 'npm-tgz', 'sources': sources, 'sha512': integrity, 'size': len(tgz),
            'entry': entry, 'binary_sha256': checksum, 'binary_size': binary_size}


def claude_code(fetch=fetch, verify=gpg_verify, log=print):
    version = fetch(f'{RELEASES}/latest', 64).decode().strip()
    if not VERSION.fullmatch(version):
        raise Refused('version pointer is malformed')
    manifest = fetch(f'{RELEASES}/{version}/manifest.json', 1 << 20)
    signature = fetch(f'{RELEASES}/{version}/manifest.json.sig', 64 << 10)
    key = fetch(KEY_URL, 256 << 10)
    if not verify(manifest, signature, key):
        raise Refused('the Claude Code release manifest signature does not verify')
    official = json.loads(manifest)
    if not isinstance(official, dict) or official.get('version', version) != version:
        raise Refused('the release manifest is for another version')
    platforms = {}
    for platform in PLATFORMS:
        try:
            platforms[platform] = npm_artifact(platform, version, official['platforms'][platform], fetch)
        except (Refused, KeyError, TypeError, ValueError, OSError, tarfile.TarError) as error:
            log(f'claude-code {platform}: left out ({type(error).__name__}: {error})')
    return {'version': version, 'platforms': platforms} if platforms else None


def github_file(found, url, fetch):
    """One release asset, downloaded once and checked against GitHub's size and SHA-256 digest."""
    if len(found) != 1:
        raise Refused(f'{len(found)} assets carry this name')
    asset = found[0]
    digest, size = asset.get('digest'), asset.get('size')
    if asset.get('browser_download_url') != url:
        raise Refused('asset URL is outside the release')
    if not isinstance(digest, str) or not digest.startswith('sha256:') or not SHA256.fullmatch(digest[7:]):
        raise Refused('asset digest is missing or malformed')
    if type(size) is not int or not 0 < size <= MAX_DOWNLOAD:
        raise Refused('asset size is malformed')
    body = fetch(url, size)
    if len(body) != size or hashlib.sha256(body).hexdigest() != digest[7:]:
        raise Refused('downloaded file does not match its digest')
    return {'kind': 'file', 'sources': [proxy + url for proxy in GITHUB_PROXIES] + [url],
            'sha256': digest[7:], 'size': size}


def cc_switch(fetch=fetch, log=print):
    release = json.loads(fetch(CC_SWITCH_API, 4 << 20))
    if not isinstance(release, dict) or release.get('draft') or release.get('prerelease'):
        raise Refused('the CC Switch release is not a published release')
    tag = release.get('tag_name')
    if not isinstance(tag, str) or not tag.startswith('v') or not VERSION.fullmatch(tag[1:]):
        raise Refused('the CC Switch tag is malformed')
    assets = {}
    for asset in release.get('assets') or []:
        if isinstance(asset, dict) and isinstance(asset.get('name'), str):
            assets.setdefault(asset['name'], []).append(asset)
    checked, platforms = {}, {}
    for platform, (pattern, kind) in CC_SWITCH_ASSETS.items():
        name = pattern.format(version=tag[1:])
        if name not in checked:
            try:
                checked[name] = github_file(assets.get(name, []), f'{CC_SWITCH_DOWNLOAD}{tag}/{name}', fetch)
            except (Refused, OSError, ValueError, TypeError, KeyError) as error:
                checked[name] = None
                log(f'cc-switch {name}: left out ({type(error).__name__}: {error})')
        if checked[name]:
            platforms[platform] = dict(checked[name], format=kind)
    return {'version': tag[1:], 'platforms': platforms} if platforms else None


def numeric_version(version):
    return tuple(int(part) for part in re.findall(r'\d+', version))


def claude_desktop(fetch=fetch, resolve=resolve, log=print):
    """Claude Desktop from Anthropic's own download host. Anthropic publishes no installer checksums, so the hash
    is computed here over TLS; at install time Gatekeeper and the msix installer still check its code signature."""
    located = {}
    for platform, (path, kind) in DESKTOP_ASSETS.items():
        try:
            url = resolve(DESKTOP_REDIRECT.format(path=path))
            match = DESKTOP_FILE.fullmatch(url) if isinstance(url, str) else None
            if not match or match['target'] != path.rsplit('/', 1)[0] or match['ext'] != kind:
                raise Refused(f'unexpected download address {url!r}')
            located[platform] = (match['version'], url, kind)
        except (Refused, OSError, ValueError) as error:
            log(f'claude-desktop {platform}: left out ({type(error).__name__}: {error})')
    if not located:
        return None
    # One version per component: platforms still on another version during a rollout wait for the next run.
    counts = collections.Counter(version for version, _, _ in located.values())
    version = max(counts, key=lambda found: (counts[found], numeric_version(found)))
    checked, platforms = {}, {}
    for platform, (found, url, kind) in located.items():
        if found != version:
            log(f'claude-desktop {platform}: left out (offers {found}, the others {version})')
            continue
        if url not in checked:
            try:
                body = fetch(url)
                if not body:
                    raise Refused('empty download')
                checked[url] = {'kind': 'file', 'sources': [url], 'sha256': hashlib.sha256(body).hexdigest(),
                                'size': len(body)}
            except (Refused, OSError, ValueError) as error:
                checked[url] = None
                log(f'claude-desktop {platform}: left out ({type(error).__name__}: {error})')
        if checked[url]:
            platforms[platform] = dict(checked[url], format=kind)
    return {'version': version, 'platforms': platforms} if platforms else None


def payload(now, components):
    components = {name: value for name, value in components.items() if value}
    if not components:
        raise Refused('no component passed its checks')
    return {'schema': SCHEMA, 'sequence': now, 'expires': now + LIFETIME, 'components': components}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if len(argv) != 1:
        sys.exit('usage: components.py <payload.json>')
    try:
        built = payload(int(time.time()), {'claude-code': claude_code(), 'cc-switch': cc_switch(),
                                           'claude-desktop': claude_desktop()})
    except (Refused, OSError, ValueError) as error:
        sys.exit(f'no manifest this run: {type(error).__name__}: {error}')
    Path(argv[0]).write_text(json.dumps(built, indent=1) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()
