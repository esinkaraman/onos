COMPILE_DEPS = CORE_DEPS + KRYO + CLI + [
    "//core/store/serializers:onos-core-serializers",
    "//core/store/primitives:onos-core-primitives",
]

osgi_jar_with_tests(
    karaf_command_packages = ["org.onosproject.ids"],
    deps = COMPILE_DEPS,
)

onos_app(
    category = "IDS",
    description = "IDS",
    title = "IDS",
    url = "http://onosproject.org",
)
