
class LogDataclass:
    """
        A class to store the normalized log with ML info

            - All data given by the log
            - Level given by Wazuh
            - Severity
            - LLM explaination 
    """
    def __init__(self, normalized_log):
        # All the data from the normalized and parsed log
        self.user               = None
        self.date               = None
        self.user               = None
        self.destination_ip     = None
        self.eventtype          = None
        self.source             = None

        # Then also whatever level Wazuh gave it?
        self.level              = None 

        # Severity scoring from ML
        self.severity           = None

        # The explaination gives from the LLM
        self.explanation        = None

    # Obtain any of the information stored in the class from a log
    def return_value(self, field_name):
        return getattr(self, field_name, None)
