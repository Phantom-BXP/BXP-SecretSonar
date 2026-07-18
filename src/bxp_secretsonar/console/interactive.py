# (contenu complet du fichier interactive.py, avec la nouvelle méthode list_candidates)

    def list_candidates(self):
        """Affiche les secrets validés avec leurs scores détaillés."""
        results = getattr(self.framework, 'validated_results', [])
        if not results:
            console.print("[yellow]Aucun résultat de scan disponible. Lancez un scan avec --console-after.[/]")
            return

        from rich.table import Table
        table = Table(title="Secrets validés (scores détaillés)")
        table.add_column("ID", style="bold", width=4)
        table.add_column("Pattern", style="cyan")
        table.add_column("Confiance", style="green", width=10)
        table.add_column("Risque Honeypot", style="red", width=16)
        table.add_column("Impact", style="yellow", width=10)
        table.add_column("Exploitable", style="bold", width=12)

        for i, v in enumerate(results):
            confidence = v.candidate.confidence_score
            risk = v.risk_score.composite_score if v.risk_score else 0.0
            impact = v.impact_score.impact_level.value if v.impact_score else "low"
            exploitable = "✅" if v.is_confirmed and confidence >= 0.7 and risk < 0.5 else "❌"
            
            table.add_row(
                str(i),
                v.candidate.evidence.pattern_name,
                f"{confidence:.2f}",
                f"{risk:.2f}",
                impact.upper(),
                exploitable
            )
        console.print(table)
        console.print("\n[dim]Utilisez 'exploit <ID>' pour lancer l'exploitation manuelle d'un candidat.[/]")
