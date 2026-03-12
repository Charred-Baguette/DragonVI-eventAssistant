try:
    from openai import OpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
import Logger

class AIinterface:
    def __init__(self, AIType, logger):
        self.AIType = AIType  # either GPTAPI or localModel
        self.logger = logger

    def print(self, message, classification, save=False, loud=True):
        message = f'[EventLogManager] {message}'
        self.logger.log(message, classification, save=save, loud=loud)


    def generate_response(self, prompt):
        if self.AIType == "GPTAPI":
            return self.generate_response_gptapi(prompt)
        elif self.AIType == "localModel":
            return self.generate_response_local_model(prompt)
        else:
            raise ValueError("Invalid AIType specified")
        
    
    def generate_response_gptapi(self, prompt):
        if self.model is None or self.client is None:
            raise ValueError("GPT API fields are not initialized")
        else:
            response = response = self.client.responses.create(
                model=self.model,
                input=prompt
            )
            return response.output_text
    def initialize_gpt_fields(self):
        # Placeholder for initializing GPT API fields
        print("Initializing GPT API fields")
        # Code to initialize fields would go here
        self.model = 'gpt-4o-mini'

    def initialize_gpt_api(self):
        if not OPENAI_AVAILABLE:
            raise ImportError("openai package not installed. Run: pip install openai")
        print("Initializing GPT API")
        self.initialize_gpt_fields()
        self.client = OpenAI()




    def generate_response_local_model(self, prompt):
        # Placeholder for local model response generation
        print("Generating response using local model")
        response = "This is a response from the local model based on the prompt: " + prompt
        return response
    
    def initialize_local_model_fields(self):
        self.localIP = "127.0.0.1"
        self.localPort = 8888
        print(f"Initialized local model fields with IP: {self.localIP} and Port: {self.localPort}")
    
    def initialize_local_model(self):
        # Placeholder for initializing local model
        print("Initializing local model")
        # Code to initialize local model would go here

    
if __name__ == "__main__":
    print("This is the AIinterface module. It should be imported and used in other parts of the application.")
    print("Example usage:")
    print("from AIinterface import AIinterface")
    print("ai = AIinterface(AIType='GPTAPI', logger=your_logger)")
    print("ai.initialize_gpt_api()")
    print("response = ai.generate_response('Your prompt here')")
    print("print(response)")

    if(input("Do you want to run a test? (y/n): ").lower() == 'y'):
        logger = Logger.Logger("AIinterfaceTest")
        ai = AIinterface(AIType='GPTAPI', logger=logger)
        ai.initialize_gpt_api()
        test_prompt = "What is the capital of France? What model am I interacting with?"
        response = ai.generate_response(test_prompt)
        print(f"Response to '{test_prompt}': {response}")