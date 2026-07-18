import asyncio
import platform
import os
from pathlib import Path
from rich.console import Console
from rich.table import Table
from bxp_secretsonar.core.queue import PriorityAsyncQueue
from bxp_secretsonar.core.models import Evidence, Candidate, Validated, ValidationResult
from bxp_secretsonar.collectors.http import HttpCollector
from bxp_secretsonar.collectors.deep_collector import DeepCollector
from bxp_secretsonar.analyzers.regex_engine import analyze_content
from bxp_secretsonar.validators.generic_http import GenericHttpValidator
from bxp_secretsonar.validators.aws_validator import AWSValidator
from bxp_secretsonar.validators.stripe_validator import StripeValidator
from bxp_secretsonar.validators.paypal_validator import PayPalValidator
from bxp_secretsonar.validators.twilio_validator import TwilioValidator
from bxp_secretsonar.validators.github_validator import GitHubValidator
from bxp_secretsonar.validators.gitlab_validator import GitLabValidator
from bxp_secretsonar.validators.gcp_validator import GCPValidator
from bxp_secretsonar.validators.slack_validator import SlackValidator
from bxp_secretsonar.validators.discord_validator import DiscordValidator
from bxp_secretsonar.validators.anthropic_validator import AnthropicValidator
from bxp_secretsonar.validators.openai_validator import OpenAIValidator
from bxp_secretsonar.validators.revolut_validator import RevolutValidator
from bxp_secretsonar.validators.twitch_validator import TwitchValidator
from bxp_secretsonar.validators.heroku_validator import HerokuValidator
from bxp_secretsonar.validators.sendgrid_validator import SendGridValidator
from bxp_secretsonar.validators.mailgun_validator import MailgunValidator
from bxp_secretsonar.validators.atlassian_validator import AtlassianValidator
from bxp_secretsonar.validators.shopify_validator import ShopifyValidator
from bxp_secretsonar.detectors.passive import analyze_passive
from bxp_secretsonar.detectors.active import probe_behavior
from bxp_secretsonar.detectors.scorer import compute_risk_score
from bxp_secretsonar.plugins.validators.protocol_prober import ProtocolProber
from bxp_secretsonar.plugins.analyzers.blast_radius import analyze_blast_radius
from bxp_secretsonar.plugins.analyzers.impact_scorer import compute_impact_score
from bxp_secretsonar.core.environment import EnvironmentProfile
from bxp_secretsonar.exploit.framework import ExploitFramework
from bxp_secretsonar.injectors.param_injector import ParamInjector

console = Console()
VALIDATION_PRIORITY_THRESHOLD = 3


class SecretSonarEngine:
    def __init__(self):
        self.env = EnvironmentProfile()
        self.queue = PriorityAsyncQueue(maxsize=self.env.max_concurrency * 5)
        self.deep_scan = False
        self.allow_private = False  # désactive la protection SSRF si True
        self.injector = None
        if self.deep_scan:
            self.collector = DeepCollector(ssl_verify=self.env.ssl_verify, max_concurrency=self.env.max_concurrency)
        else:
            self.collector = HttpCollector(ssl_verify=self.env.ssl_verify, max_concurrency=self.env.max_concurrency)
        self.validator_generic = GenericHttpValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_aws = AWSValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_stripe = StripeValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_paypal = PayPalValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_twilio = TwilioValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_github = GitHubValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_gitlab = GitLabValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_gcp = GCPValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_slack = SlackValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_discord = DiscordValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_anthropic = AnthropicValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_openai = OpenAIValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_revolut = RevolutValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_twitch = TwitchValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_heroku = HerokuValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_sendgrid = SendGridValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_mailgun = MailgunValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_atlassian = AtlassianValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.validator_shopify = ShopifyValidator(ssl_verify=self.env.ssl_verify, timeout=5.0)
        self.prober = ProtocolProber()
        self._running = False
        self._validated_results: list[Validated] = []
        self.framework = None
        self.min_confidence = 0.7
        self.min_impact = "low"
        self.honeypot_threshold = 0.5

    async def run(self, targets: list[str]) -> None:
        console.print("[bold green]🚀 BXP-SecretSonar v0.5.0-alpha[/]")
        console.print(f"[dim]Environment: {self.env.summary()}[/]\n")
        self._running = True
        await self.collector.start()
        try:
            tasks = [self._process_target(t) for t in targets]
            await asyncio.gather(*tasks, return_exceptions=True)
        finally:
            await self.collector.close()
        self._display_results()
        confirmed = sum(1 for v in self._validated_results if v.is_confirmed)
        high_impact = sum(1 for v in self._validated_results if v.impact_score and v.impact_score.composite_score >= 0.6)
        console.print(f"\n[bold green]✅ Scan complete. {len(self._validated_results)} validated, {confirmed} confirmed, {high_impact} high-impact.[/]")

    async def _process_target(self, url: str) -> None:
        try:
            artifact = await self.collector.collect(url)
            if not artifact:
                return
            if self.injector:
                try:
                    injected = await self.injector.inject(artifact)
                    for inj in injected:
                        artifact.content += '\n--- INJECTED ---\n' + inj.content
                        artifact.metadata['injected'] = True
                except Exception as e:
                    console.print(f'[yellow]Injection error: {e}[/]')

            passive_signals = analyze_passive(artifact)
            active_signals = await probe_behavior(url, ssl_verify=self.env.ssl_verify, timeout=3.0)
            risk_score = compute_risk_score(url, passive_signals, active_signals)
            raw_evidences = analyze_content(artifact.content, artifact.id)
            for ev_data in raw_evidences:
                evidence = Evidence(**ev_data)
                candidate = Candidate(
                    evidence=evidence,
                    confidence_score=ev_data['base_confidence'],
                    priority=max(1, min(10, int((1.0 - ev_data['base_confidence']) * 10)))
                )
                await self.queue.put(candidate)
                if candidate.priority <= VALIDATION_PRIORITY_THRESHOLD:
                    validated = await self._route_validator(candidate)
                    validated.risk_score = risk_score
                    blast_radius = analyze_blast_radius(evidence.context_before, evidence.context_after)
                    protocol_probe = None
                    if evidence.pattern_name in ("generic_api_key", "bearer_token"):
                        protocol_probe = await self.prober.probe("http", url, evidence.matched_value, timeout=3.0)
                    elif evidence.pattern_name == "private_key_header":
                        protocol_probe = await self.prober.probe("ssh", url, timeout=3.0)
                    validated.impact_score = compute_impact_score(
                        secret_type=evidence.pattern_name,
                        probe_result=protocol_probe,
                        blast_radius=blast_radius,
                    )
                    self._validated_results.append(validated)

                    if self.framework:
                        try:
                            do_exploit = True
                            if validated.candidate.confidence_score < self.min_confidence:
                                do_exploit = False
                            if validated.impact_score:
                                impact_levels = ["low", "medium", "high", "critical"]
                                if impact_levels.index(validated.impact_score.impact_level.value) < impact_levels.index(self.min_impact):
                                    do_exploit = False
                            if validated.risk_score and validated.risk_score.composite_score >= self.honeypot_threshold:
                                do_exploit = False
                            if do_exploit:
                                exploit_results = self.framework.run_exploit(validated, strategy="safe")
                                for er in exploit_results:
                                    console.print(f"[bold cyan][EXPLOIT][/] {er.plugin_name}: {er.output[:100]}")
                            else:
                                console.print(f"[yellow][SKIP][/] Secret {validated.candidate.evidence.matched_value[:20]}... ignoré (scores insuffisants)")
                        except Exception as ex:
                            console.print(f"[red]Exploit error: {ex}[/]")
        except Exception as e:
            console.print(f"[red]❌ Error processing {url}: {e}[/]")

    async def _route_validator(self, candidate: Candidate) -> Validated:
        p = candidate.evidence.pattern_name.lower()
        if 'aws' in p:
            return await self.validator_aws.validate(candidate)
        elif 'stripe' in p:
            return await self.validator_stripe.validate(candidate)
        elif 'paypal' in p:
            return await self.validator_paypal.validate(candidate)
        elif 'twilio' in p:
            return await self.validator_twilio.validate(candidate)
        elif 'github' in p:
            return await self.validator_github.validate(candidate)
        elif 'gitlab' in p:
            return await self.validator_gitlab.validate(candidate)
        elif 'gcp' in p or 'google' in p:
            return await self.validator_gcp.validate(candidate)
        elif 'slack' in p:
            return await self.validator_slack.validate(candidate)
        elif 'discord' in p:
            return await self.validator_discord.validate(candidate)
        elif 'anthropic' in p or 'claude' in p:
            return await self.validator_anthropic.validate(candidate)
        elif 'openai' in p:
            return await self.validator_openai.validate(candidate)
        elif 'revolut' in p:
            return await self.validator_revolut.validate(candidate)
        elif 'twitch' in p:
            return await self.validator_twitch.validate(candidate)
        elif 'heroku' in p:
            return await self.validator_heroku.validate(candidate)
        elif 'sendgrid' in p:
            return await self.validator_sendgrid.validate(candidate)
        elif 'mailgun' in p:
            return await self.validator_mailgun.validate(candidate)
        elif 'atlassian' in p or 'jira' in p or 'confluence' in p:
            return await self.validator_atlassian.validate(candidate)
        elif 'shopify' in p:
            return await self.validator_shopify.validate(candidate)
        else:
            return await self.validator_generic.validate(candidate)

    def _display_results(self) -> None:
        if not self._validated_results:
            console.print("[yellow]No secrets detected.[/]")
            return
        table = Table(title="Validated Secrets + Impact", show_lines=True)
        table.add_column("Status", style="bold", width=12)
        table.add_column("Impact", style="bold", width=10)
        table.add_column("Pattern", style="cyan")
        table.add_column("Value", style="red", max_width=25)
        table.add_column("Risk", width=8)
        table.add_column("Blast Radius", style="dim", max_width=30)
        for v in sorted(self._validated_results, key=lambda x: x.candidate.priority):
            status_style = "green" if v.is_confirmed else ("red" if v.result == ValidationResult.REJECTED else "yellow")
            val = v.candidate.evidence.matched_value
            impact_str = "-"
            impact_style = "dim"
            if v.impact_score:
                impact_str = v.impact_score.impact_level.value.upper()
                impact_style = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "green"}.get(v.impact_score.impact_level.value, "dim")
            risk_str = f"{v.risk_score.composite_score:.2f}" if v.risk_score else "-"
            br_str = "-"
            if v.impact_score and v.impact_score.blast_radius:
                br_items = [f"{b.resource_type}:{b.identifier[:20]}" for b in v.impact_score.blast_radius[:2]]
                br_str = ", ".join(br_items)
            table.add_row(
                f"[{status_style}]{v.result.value}[/]",
                f"[{impact_style}]{impact_str}[/]",
                v.candidate.evidence.pattern_name,
                val[:25] + ("..." if len(val) > 25 else ""),
                risk_str,
                br_str,
            )
        console.print(table)

    async def shutdown(self) -> None:
        self._running = False
        await self.queue.shutdown()
        await self.collector.close()
        console.print("\n[bold red]🛑 Engine stopped gracefully[/]")
