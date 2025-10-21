rule OpenDetectTest {
    meta:
      description = """
        This signature is used as a test for the 
        open-detect engine and not malicious.
        """
    strings:
        $text = "b3BlbmRldGVjdAo="
    condition:
        $text
}
