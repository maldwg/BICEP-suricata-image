from abc import ABC, abstractmethod

class IDSBase(ABC):
    """
    Abstract base class for all IDS supported by BICEP
    Each IDS involved needs to inherit from this base class and implement the following methods nad attributes
    """
    
    # @property
    # @abstractmethod
    # def attribute(self):
    #     pass

    @abstractmethod
    def configure(self):
        """
        Method for setting up the main configuration file in the corresponding location
        gets a file content as input and needs to save it to the location necesary for the IDS system
        """
        return "base implementation"

        
    # @abstractmethod
    # def startStaticAnalysis(self):
    #     pass

        
    # @abstractmethod
    # def startNetworkAnalysis(self):
    #     pass


        
    # @abstractmethod
    # def stopAnalysis(self):
    #     pass

        
    # def sendMetrics(self):
    #     pass

    
    # def sendAlerts(self):
    #     pass

        
    # @abstractmethod
    # def configure(self):
    #     pass