This package contains helper classes for [open-jarvis](https://github.com/open-jarvis) applications.


## Classes
- [Colors](#colors)
- [Config](#config)
- [Exiter](#exiter)
- [Jarvis](#jarvis)
- [Logger](#logger)
- [MQTT](#mqtt)
- [SetupTools](#setuptools)



### Colors
```python
Colors
	.PURPLE = '\033[95m'
	.BLUE 	= '\033[94m'
	.CYAN 	= '\033[96m'
	.GREEN 	= '\033[92m'
	.YELLOW = '\033[93m'
	.RED 	= '\033[91m'
	.END 	= '\033[0m'
	.RESET	= '\033[0m'

	.WARNING= YELLOW
	.ERROR	= RED
```


### Config  
```python
Config(user, filename="main.conf") # initialize the configuration in /home/{user}/.config/jarvis/{filename}
	.exists() # returns true or false if the config file exists
	.create() # create an empty configuration
	.create_if_not_exists() # .create() if not .exists()
	.get() # get entire configuration
	.get_key(key) # get key from configuration
	.set_key(key, value) # set a key in configuration
```


### Exiter  
```python
def on_exit(args):
	print("exiting... perform actions here!")

Exiter(on_exit, [args, ...]) 	# initializes an Exiter who executes the given function
								# when the script receives a SIGTERM or SIGINT signal
```


### Jarvis  
> This class is still in development  

```python
Jarvis(host="127.0.0.1", port=1883, client_id="mqtt_jarvis")
	.register()
	.get_devices()
	.get_property(key, target_token=None)
	.set_property(target_token, key, value)
	.instant_ask(typ, name, infos, options)
	.instant_answer(target_token, typ, option_index, description)
	.instant_scan(target_token=None, typ=None)
	.instant_delete(target_token)
```


### Logger  
Provides a uniform interface for logging files

```python
Logger(logfile, compressed_folder)
	.on() # turn on logging
	.off() # turn off logging

	.console_on() # turn on console logging
	.console_off() # turn off console logging

	.new_group() # turn on grouping and create a new logging group (only for fast RAM logging)
	.enable_fast() # enable fast RAM logging
	.disable_fast() # disable fast RAM logging
	.clear_fast() # clear fast RAM logging data
	.get_fast()	 # get fast RAM logs

	.i(tag, message) # create an info message
	.e(tag, message) # create an error message
	.w(tag, message) # create a warning message
	.s(tag, message) # create a success message
	.c(tag, message) # create a critical message
```


### MQTT
```python
MQTT(host=127.0.0.1, port=1883, client_id=[random])
	.on_connect(callback[client, userdata, flags, rc]) # on connect event
	.on_message(callback[client, userdata, message]) # on message callback: topic = message.topic, data = message.payload.decode()
	.publish(topic, payload) # public a str message under str topic
	.subscribe(topic) # subscribe to a topic (# = all)
```


### SetupTools
```python
SetupTools
	.do_action(print_str, shell_command, show_output=True, on_fail="failed!", on_success="done!", exit_on_fail=True): # run a shell command
	.regex_replace_in_file(file_path, from_regex, to_string) # replace regex in file
	.is_root() # check if has root access
	.get_python_version() # get the executing python version
	.check_python_version(version): # make sure get_python_version() == version, exit on fail
	.check_root() # make sure is_root() == True, exit on fail
	.get_default_installation_dir(default_dir) # ask for the default Jarvis installation directory, return either default_dir or a new directory
	.get_default_user(default_user) # ask for the default user, return either default_user or a new username
```



