import pulumi
import pulumi_cloudflare as cloudflare
from var import customer1_vars

def manage_customer1_resources():

### DNS > Records ###
# Free+

    cf_record = cloudflare.Record(customer1_vars["dns_record"]["name"],
        name=customer1_vars["dns_record"]["hostname"],
        zone_id=customer1_vars["zone_id"],
        type=customer1_vars["dns_record"]["type"],
        value=customer1_vars["dns_record"]["value"],
        ttl=customer1_vars["dns_record"]["ttl"]
    )

### DNS > Settings ###
# Free+

    zone_settings = cloudflare.ZoneSettingsOverride("zoneSettings",
        zone_id=customer1_vars["zone_id"],
        settings={
            "cname_flattening": "flatten_all"
        }
    )

### Security > WAF > Custom Rules ###
# Free+

    custom_rules = [cloudflare.RulesetRuleArgs(**rule) for rule in customer1_vars["custom_rules"]]

# Update Custom Ruleset

    custom_ruleset = cloudflare.Ruleset("update-custom-ruleset",
        zone_id=customer1_vars["zone_id"],
        name="Custom Ruleset",
        description="Update Custom Ruleset",
        kind="zone",
        phase="http_request_firewall_custom",
        rules=custom_rules
    )

### Security > WAF > Managed rules > Cloudflare Managed Ruleset ###
# Pro+

    managed_rules = [cloudflare.RulesetRuleArgs(**rule) for rule in customer1_vars["managed_rules"]]

# Update Cloudflare Managed Ruleset

    managed_rulesets = cloudflare.Ruleset("update-managed-rulesets",
        zone_id=customer1_vars["zone_id"],
        name="Managed Ruleset",
        description="Update Managed Rulesets",
        kind="zone",
        phase="http_request_firewall_managed",
        rules=managed_rules
    )

### Security Settings > Bots > Enable Bot Fight Mode ###
# Free+

    bot_mode = cloudflare.BotManagement("enable-bot-fight-mode",
        zone_id=customer1_vars["zone_id"],
        fight_mode=customer1_vars["bot_management"]["fight_mode"]
    )

### Security Settings > Bots > Configure Super Bot Fight Mode ###
# Pro+

    bot_fight_mode = cloudflare.BotManagement("configure-super-bot-fight-mode",
        zone_id=customer1_vars["zone_id"],
        enable_js=customer1_vars["bot_management"]["enable_js"],
        sbfm_definitely_automated=customer1_vars["bot_management"]["sbfm_definitely_automated"],
        sbfm_verified_bots=customer1_vars["bot_management"]["sbfm_verified_bots"],
        sbfm_static_resource_protection=customer1_vars["bot_management"]["sbfm_static_resource_protection"],
        optimize_wordpress=customer1_vars["bot_management"]["optimize_wordpress"]
    )

### Security > Settings ###
# Free+

    security_settings = cloudflare.ZoneSettingsOverride(
        "configure-security-settings",
        zone_id=customer1_vars["zone_id"],
        settings=customer1_vars["security_settings"]
    )

### Rules > Transform Rules ###
# Free+

    response_transform_rules = [
        cloudflare.RulesetRuleArgs(
            description="Modify Content Security Policy",
            action="rewrite",
            action_parameters=cloudflare.RulesetRuleActionParametersArgs(
                headers=[
                    {
                        "name": "Content-Security-Policy",
                        "operation": "set",
                        "value": customer1_vars["response_headers"]["csp"]
                    },
                    {
                        "name": "Referrer-Policy",
                        "operation": "set",
                        "value": customer1_vars["response_headers"]["referrer_policy"]
                    },
                    {
                        "name": "Reporting-Endpoints",
                        "operation": "set",
                        "value": customer1_vars["response_headers"]["reporting_endpoints"]
                    },
                    {
                        "name": "X-Content-Type-Options",
                        "operation": "set",
                        "value": customer1_vars["response_headers"]["x_content_type_options"]
                    },
                    {
                        "name": "X-Frame-Options",
                        "operation": "set",
                        "value": customer1_vars["response_headers"]["x_frame_options"]
                    }
                ]
            ),
            expression="true",
            enabled=True
        )
    ]

# Manage Transform Rules

    response_header_ruleset = cloudflare.Ruleset("manage-response-header-transform-ruleset",
        zone_id=customer1_vars["zone_id"],
        name="Response Header Transform Ruleset",
        description="Manage Response Header Transform Ruleset",
        kind="zone",
        phase="http_response_headers_transform",
        rules=response_transform_rules
    )

# Return Resources

    return {
        "cf_record": cf_record,
        "zone_settings": zone_settings,
        "custom_ruleset": custom_ruleset,
        "managed_rulesets": managed_rulesets,
        "bot_mode": bot_mode,
        "bot_fight_mode": bot_fight_mode,
        "security_settings": security_settings,
        "response_header_ruleset": response_header_ruleset
    }