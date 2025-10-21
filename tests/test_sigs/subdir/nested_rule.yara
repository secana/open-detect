rule NestedTestRule {
    meta:
      description = """
        This is a nested test rule in a subdirectory.
        Used to test recursive directory scanning.
        """
    strings:
        $nested = "NESTED_TEST_SIGNATURE"
    condition:
        $nested
}
