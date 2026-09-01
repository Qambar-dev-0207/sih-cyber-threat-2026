"""
SIH26145 - Synthetic Threat Scenario Generation Package
Provides deterministic alert generation for APT, DDoS, C2 Beaconing, and DNS Tunneling scenarios.
"""

from src.api.simulation.scenario_generator import (
    generate_apt_scenario,
    generate_c2_scenario,
    generate_ddos_scenario,
    generate_dns_tunnel_scenario,
    generate_scenario_alerts,
)

__all__ = [
    "generate_apt_scenario",
    "generate_ddos_scenario",
    "generate_c2_scenario",
    "generate_dns_tunnel_scenario",
    "generate_scenario_alerts",
]
