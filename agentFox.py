import yara
import os
import ConfigParser


def agentfox_conf(agentfox_get_section, agentfox_get_value):
	configuration = ConfigParser.ConfigParser()
	configuration.read("agentfox.ini")
	return(configuration.get(agentfox_get_section, agentfox_get_value))



current_directory = os.getcwd()
yara_rules_directory = current_directory + '\\' + agentfox_conf('YaraRulesPath', 'path')
yara_rules_directory_files = os.listdir(yara_rules_directory)
yara_rules_directory_checker = os.path.isdir(yara_rules_directory)


scaning_path_directory = agentfox_conf('ScaningPath', 'path')
scaning_path_directory_checker = os.path.isdir(scaning_path_directory)
scaning_path_directory_files = os.listdir(scaning_path_directory)


def file_loader(file_loader_path, file_dir, result=[]):
	for file in file_dir:
		file_loader_path_full = file_loader_path + file
		result.append(file_loader_path_full)
	return(result)

def yara_file_loader(file_loader_path, file_dir, result=[]):
	for file in file_dir:
		file_loader_path_full = file_loader_path + file
		result.append(file_loader_path_full)
	return(result)

	
def check_yar_no_empty(yar_path, rule_dot_yar=[]):
	for file in yar_path:
		if file.endswith(".yar"):
			rule_dot_yar.append("1")
	return(rule_dot_yar)

def yara_load_to_compile(yara_files,compile_filepaths=[]):
	for yar_file_order in range(len(check_yar_no_empty(yara_rules_directory_files))):
		yar_file_order_str = str(yar_file_order)
		compile_filepaths.append("main"+yar_file_order_str+":"+yara_files[yar_file_order])
	return(compile_filepaths)

def yara_matches(yara_rules_path, files_to_be_scanned, result=[]):
	for scanning_files in files_to_be_scanned:
		for yar_rule in yara_rules_path:
			yara_rule_scan = yara.compile(yar_rule)
			matches = yara_rule_scan.match(scanning_files)
			if matches <> []:
				result.append("file: "+str(scanning_files)+" matched yara rule: "+str(matches))
	return(result)



print(yara_matches(yara_file_loader(yara_rules_directory,yara_rules_directory_files), file_loader(scaning_path_directory,scaning_path_directory_files)))
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	