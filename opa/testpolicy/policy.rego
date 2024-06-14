package fairwinds

insecureCapabilitiesAdded[actionItem] {
        initContainers := object.get(input.spec.template.spec, "initContainers", [])
        containers := input.spec.template.spec.containers
        allContainers := array.concat(containers, initContainers)

        container := allContainers[_]

        violations := [sprintf("Container %v is adding security capabilities: %v", [container.name, container.securityContext.capabilities.add]) |
                container := allContainers[_]
                added_capabilities := container.securityContext.capabilities.add
                count(added_capabilities) > 0
        ]

        count(violations) > 0

        description := concat("\n", violations)

        actionItem := {
                "title": "Added container security capabilities found",
                "description": description,
                "severity": 0.1,
                "remediation": "Remove the added capabilities from the security context of the deployment's containers.",
                "category": "Security",
        }
}
