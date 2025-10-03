FROM marty-base:latest

# Copy test-specific code 
COPY src/test_main.py ./src/

# Command to run tests
CMD ["python", "/app/src/test_main.py"]