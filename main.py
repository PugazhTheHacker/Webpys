"""CyberScan CLI - basic orchestrator"""
import argparse
from scanners.port_scanner import scan_ports
from recon.subdomain_scanner import find_subdomains
from recon.dir_scanner import scan_dirs
from reports.reporter import Reporter

# Banner (webpys v3.0.1) - blue hacker theme
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    with open('assets/banner.txt', 'r', encoding='utf-8') as _b:
        banner_lines = _b.read().splitlines()

    colored_banner = []
    for line in banner_lines:
        stripped = line.strip()
        if not stripped:
            colored_banner.append(line)
        elif stripped.startswith('Author:') or stripped.startswith('https://github.com/'):
            colored_banner.append(Fore.BLUE + Style.BRIGHT + line)
        else:
            colored_banner.append(Fore.YELLOW + Style.BRIGHT + line)

    print('\n'.join(colored_banner))
except Exception:
    # Fallback: simple banner
    print('webpys v3.0.1 - CyberScan')


def parse_ports(ports_str):
    if not ports_str:
        return list(range(1,1025))
    parts = []
    for p in ports_str.split(','):
        if '-' in p:
            a,b = p.split('-')
            parts.extend(range(int(a), int(b)+1))
        else:
            parts.append(int(p))
    return sorted(set(parts))


def main():
    parser = argparse.ArgumentParser(description='CyberScan - Recon & Scanning Toolkit')
    parser.add_argument('--target', required=True, help='Target domain or IP')
    parser.add_argument('--ports', help='Ports (e.g. 22,80,8000-8100)')
    parser.add_argument('--subdomains', help='Subdomain wordlist path (optional)')
    parser.add_argument('--dirs', help='Directory wordlist path (optional)')
    parser.add_argument('--output', default='reports/result', help='Output path prefix')
    parser.add_argument('--all', action='store_true', help='Run all checks')

    args = parser.parse_args()

    reporter = Reporter(args.output)

    ports = parse_ports(args.ports)

    if args.all or args.subdomains:
        wordlist = args.subdomains or 'wordlists/subdomains.txt'
        subs = find_subdomains(args.target, wordlist)
        reporter.add('subdomains', subs)

    if args.all or args.ports:
        pfind = scan_ports(args.target, ports)
        reporter.add('open_ports', pfind)

    if args.all or args.dirs:
        w = args.dirs or 'wordlists/dirs.txt'
        dfind = scan_dirs(args.target, w)
        reporter.add('found_paths', dfind)

    # Placeholder vulnerability checks would be added here
    reporter.save()
    print('Scan complete. Reports saved to', reporter.out_json)


if __name__ == '__main__':
    main()
