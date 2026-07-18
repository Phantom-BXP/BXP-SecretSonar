import asyncio, click, pickle, os, tempfile
from rich.console import Console
from bxp_secretsonar.core.engine import SecretSonarEngine
from bxp_secretsonar.exploit.framework import ExploitFramework

console = Console()

@click.group()
def cli():
    pass

@cli.command()
@click.option('--target', '-t', required=True, help='Target URL to scan')
@click.option('--exploit', is_flag=True, help='Enable exploitation of confirmed secrets (DANGER)')
@click.option('--authorized', is_flag=True, help='Confirm you have WRITTEN authorization')
@click.option('--strategy', type=click.Choice(['safe', 'aggressive']), default='safe', help='Exploitation strategy')
@click.option('--min-confidence', type=float, default=0.7, help='Confiance minimale pour exploiter (0.0-1.0)')
@click.option('--min-impact', type=click.Choice(['low', 'medium', 'high', 'critical']), default='low', help='Impact minimum requis')
@click.option('--honeypot-threshold', type=float, default=0.5, help='Score honeypot max avant de refuser l\'exploitation')
@click.option('--deep', is_flag=True, help='Active le DeepScan (analyse JS, headers, robots.txt, etc.)')
@click.option('--console-after', is_flag=True, help='Launch interactive console after scan with obtained sessions')
def scan(target, exploit, authorized, strategy, console_after, min_confidence, min_impact, honeypot_threshold, deep):
    """Run SecretSonar with optional exploitation."""
    if exploit and not authorized:
        console.print("[bold red]ERROR: Exploitation requires --authorized flag. Aborting.[/]")
        return

    engine = SecretSonarEngine()
    engine.deep_scan = deep
    engine.min_confidence = min_confidence
    engine.min_impact = min_impact
    engine.honeypot_threshold = honeypot_threshold
    if exploit and authorized:
        engine.framework = ExploitFramework(authorized=True)
        console.print("[bold yellow]⚠️  EXPLOIT MODE ENABLED[/]")

    async def run():
        await engine.run([target])

    asyncio.run(run())

    if console_after and engine.framework and engine.framework.sessions:
        console.print(f"[green]{len(engine.framework.sessions)} session(s) exploitable(s) disponibles.[/]")
        fd, path = tempfile.mkstemp(suffix=".session")
        with os.fdopen(fd, 'wb') as f:
            pickle.dump(engine.framework, f)
        console.print("[dim]Lancement de la console interactive...[/]")
        from bxp_secretsonar.console.interactive import launch_interactive_console
        launch_interactive_console(engine.framework)
        os.unlink(path)
    elif console_after:
        console.print("[yellow]Aucune session n'a été créée, console non lancée.[/]")

@cli.command()
@click.option('--authorized', is_flag=True, help='Confirmer l\'autorisation écrite')
@click.option('--load-sessions', type=click.Path(exists=True), help='Fichier de sessions sauvegardé')
def console_cmd(authorized, load_sessions):
    """Lancer la console interactive post-exploitation."""
    if not authorized:
        console.print("[bold red]ERROR: La console nécessite --authorized. Abandon.[/]")
        return
    from bxp_secretsonar.exploit.framework import ExploitFramework
    from bxp_secretsonar.console.interactive import launch_interactive_console

    if load_sessions:
        import pickle
        with open(load_sessions, 'rb') as f:
            fw = pickle.load(f)
        console.print(f"[green]Sessions chargées depuis {load_sessions}[/]")
    else:
        fw = ExploitFramework(authorized=True)
    launch_interactive_console(fw)

@cli.command()
@click.option('--query', '-q', required=True, help='Mot-clé ou filtre (ex: "nginx", "product:Apache")')
@click.option('--provider', '-p', help='Provider à utiliser (shodan, crtsh, firecrawl)')
@click.option('--limit', '-l', default=10, help='Nombre maximum de résultats')
@click.option('--scan', is_flag=True, help='Scanner automatiquement les cibles découvertes')
def discover(query, provider, limit, scan):
    """Découvre des cibles via des providers (Shodan, CRT.sh, etc.) et les scanne optionnellement."""
    from bxp_secretsonar.discovery.manager import DiscoveryManager
    manager = DiscoveryManager()
    urls = asyncio.run(manager.run(query=query, limit=limit, provider=provider))
    if not urls:
        console.print("[!] Aucune URL trouvée.")
        return
    console.print(f"\n[+] {len(urls)} cible(s) découverte(s) :")
    for u in urls:
        console.print(f"    {u}")
    if scan:
        console.print("\n[+] Lancement du scan sur les cibles...")
        engine = SecretSonarEngine()
        asyncio.run(engine.run(urls))

if __name__ == '__main__':
    cli()

app = cli
