#include <string>
#include <iostream>
#include <set>
#include <map>
#include <sstream>
#include <unordered_map>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <getopt.h>
#include <malloc.h>
#include <ctime>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <cstdlib>
#include <nlohmann/json.hpp>
#include <regex>
#include <memory>
#include <array>

using json = nlohmann::json;

extern "C"
{
#include <config/kube_config.h>
#include <config/incluster_config.h>
#include <api/CoreV1API.h>
#include <api/AppsV1API.h>
#include <external/cJSON.h>
}

#include <sys/stat.h>
#include "timeloops.h"
#include "timeloops.skel.h"
using namespace std;

#define DEBUG

struct timeloops_bpf *skel;
int container_types_map_fd;
int container_ids_map_fd;
apiClient_t *apiClient;
string my_container_id;
string my_pod_name;
string my_node_name;
map<string, string> image_pairs;							// map production images to oracle images
map<string, char> image_types;								// maps image name to unknown, not timelooping, oracle, or production
map<string, char> container_types;						// maps container ID to unknown, not timelooping, oracle, or production
map<string, string> container_to_pod_map;			// TODO: delete this maps container to its pod name
map<string, string> pod_to_container_map;			// maps a pod to its container
map<string, string> container_to_image_map;		// maps container to its image name
map<string, string> image_to_deployment;			// TODO: delete this becuase it should be a map from deployment to image pairs and then we have to search the deployment, causing an issue for DSB
map<string, pair<string, string>> config_map; // TODO: use this to replace image_to_deployment and image_pairs
map<string, int> policy_ids;									// maps deployment name to its policy ID for eBPF map container_ids
int curr_num_timelooping_containers;					// number of timelooping services on the current node
map<string, time_t> oracle_containers_to_start_times;
time_t last_checked_oracles;
map<string, string> sha_to_image_name_map;

///////// PRINT HELPER FUNCTIONS ///////////////////////////////////////////////

static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

void printCurrentTime()
{
	// Get the current time as a time_point
	auto now = std::chrono::system_clock::now();

	// Convert to time_t for time formatting
	std::time_t now_time_t = std::chrono::system_clock::to_time_t(now);

	// Convert to milliseconds since epoch
	auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
	auto value = now_ms.time_since_epoch();
	long duration = value.count();

	// Extract milliseconds from the duration
	long milliseconds = duration % 1000;

	// Convert time_t to tm structure for local time
	std::tm *localTime = std::localtime(&now_time_t);

	// Print the time with milliseconds
	std::cout << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
	std::cout << '.' << std::setw(3) << std::setfill('0') << milliseconds << '\n';
}

std::string getImageSHA(const std::string &imageName, const std::string &namespaceName = "k8s.io")
{
	// Use ctr to list all images in the given namespace
	std::string command = "ctr --namespace " + namespaceName + " images list";

	std::array<char, 4096> buffer;
	std::string result;

	std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
	if (!pipe)
	{
		std::cerr << "Failed to run ctr command." << std::endl;
		return "";
	}

	while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr)
	{
		result += buffer.data();
	}

	std::istringstream iss(result);
	std::string line;

	// Skip the header
	std::getline(iss, line);

	// Parse each line to find the matching image
	while (std::getline(iss, line))
	{
		std::istringstream linestream(line);
		std::string ref, type, digest;

		linestream >> ref >> type >> digest;

		if (ref == imageName)
		{
			return digest;
		}
	}

	std::cerr << "Image name '" << imageName << "' not found in containerd image list." << std::endl;
	return "";
}

std::string extract_app_name_from_pod(const std::string &str)
{
	int lastIndex = str.find_last_of('-');
	if (lastIndex == std::string::npos)
	{
		// If there's no dash, return the whole string
		return str;
	}

	int secondToLastIndex = str.find_last_of('-', lastIndex - 1);
	if (secondToLastIndex == std::string::npos)
	{
		// If there's only one dash, return the whole string
		return str;
	}

	return str.substr(0, secondToLastIndex);
}

char *extract_container_id(const char *input)
{
	const char *prefix1 = "docker://";
	const char *prefix2 = "containerd://"; // Keeping this in case there are mixed environments

	const char *start = input;

	// Check if the string starts with one of the prefixes
	if (strstr(input, prefix1) == input)
	{
		start += strlen(prefix1);
	}
	else if (strstr(input, prefix2) == input)
	{
		start += strlen(prefix2);
	}

	// Find the end of the container ID
	const char *end = start;
	while (*end && *end != '.' && *end != '/')
	{
		end++;
	}

	// Allocate memory for the container ID
	char *containerID = (char *)malloc(end - start + 1);
	if (!containerID)
	{
		return NULL; // Memory allocation failed
	}

	// Copy the container ID into the allocated memory
	strncpy(containerID, start, end - start);
	containerID[end - start] = '\0'; // Null-terminate the string

	return containerID;
}

char *get_container_id_from_cgroup_path(char *cgroup_path)
{
	char *start = NULL;

	// Find the last occurrence of '/' for dockerd
	if (strstr(cgroup_path, "/docker/") != NULL)
	{
		start = strstr(cgroup_path, "/docker/") + 8; // Skip "/docker/"
	}
	else
	{
		// Fallback for other runtimes
		start = strrchr(cgroup_path, '/');
		if (start != NULL)
		{
			start += 1;
		}
		else
		{
			start = (char *)cgroup_path;
		}
	}

	// Allocate memory for the container ID
	int id_length = strlen(start);
	char *container_id = (char *)malloc((id_length + 1) * sizeof(char));
	if (container_id != NULL)
	{
		strncpy(container_id, start, id_length);
		container_id[id_length] = '\0';

		// Remove any newline character
		char *newline_pos = strchr(container_id, '\n');
		if (newline_pos != NULL)
		{
			*newline_pos = '\0';
		}
	}
	return container_id;
}

///////// STRING HELPER FUNCTIONS //////////////////////////////////////////////

bool is_substring(string needle, string s)
{
	return s.find(needle) != string::npos;
}

string find_substring_id(const string &s, const std::string &needle)
{
	size_t startPos = string::npos;

	// Try to find an exact match first
	startPos = s.find(needle);

	// If no exact match is found, try fuzzy matching
	if (startPos == string::npos)
	{
		for (size_t i = 0; i <= s.length() - needle.length(); ++i)
		{
			size_t mismatchCount = 0;
			for (size_t j = 0; j < needle.length() && i + j - mismatchCount < s.length(); ++j)
			{
				if (needle[j] != s[i + j - mismatchCount])
				{
					if (++mismatchCount > 1)
						break; // Allow up to one mismatch
				}
			}
			if (mismatchCount <= 1)
			{
				startPos = i;
				break;
			}
		}
	}

	if (startPos == string::npos)
	{
		// Needle not found
		return "";
	}

	// Adjust starting position to search for the quotation mark after the needle (or its misspelled variant)
	startPos += needle.length() - (startPos + needle.length() > s.length() ? 1 : 0);

	// Find the next quotation mark or comma after the needle
	size_t endPosQuote = s.find('"', startPos);
	size_t endPosComma = s.find(',', startPos);
	if (endPosQuote == std::string::npos && endPosComma == std::string::npos)
	{
		// Neither quotation mark nor comma found after needle
		return "";
	}

	size_t endPos = endPosQuote < endPosComma ? endPosQuote : endPosComma;

	// Extract the substring from the end of the needle to the next quotation mark or comma
	std::string result = s.substr(startPos, endPos - startPos);

#ifdef DEBUG
	if (result.length() == 0)
	{
		std::cout << "WARNING: id for needle " << needle << " is not found" << std::endl;
	}
#endif

	return result;
}

bool is_almost_equal(const std::string &s1, const std::string &s2, int tolerance)
{
	// Check if the absolute difference in length is within the tolerance
	int lenDiff = std::abs(static_cast<int>(s1.length()) - static_cast<int>(s2.length()));
	if (lenDiff > tolerance)
	{
		return false;
	}

	int i = 0, j = 0;
	int edits = 0;
	while (i < s1.length() && j < s2.length())
	{
		// If characters match, move to the next character in both strings
		if (s1[i] == s2[j])
		{
			i++;
			j++;
		}
		else
		{
			// If they don't match, consider this an edit
			edits++;
			if (edits > tolerance)
			{
				return false;
			}

			// If possible, try moving forward in the longer string (or both if they are the same length)
			if (s1.length() > s2.length())
			{
				i++;
			}
			else if (s2.length() > s1.length())
			{
				j++;
			}
			else
			{
				i++;
				j++;
			}
		}
	}

	// Account for any remaining characters in either string
	edits += std::abs(static_cast<int>(s1.length() - i) - static_cast<int>(s2.length() - j));
	std::cout << "comparing " << s1 << " and " << s2 << "result: " << edits << std::endl;

	return edits <= tolerance;
}

///////// GET INFO ABOUT TIMELOOPS CONTAINER/POD/NODE //////////////////////////

char *get_my_container_name()
{
	FILE *fp;
	char buffer[BUFFER_SIZE];
	char *container_id = NULL;

	// Open the /proc/self/cgroup file for reading
	fp = fopen("/proc/self/cgroup", "r");
	if (fp == NULL)
	{
		perror("Error opening /proc/self/cgroup");
		return NULL;
	}

	// Read lines from /proc/self/cgroup
	while (fgets(buffer, BUFFER_SIZE, fp) != NULL)
	{
		// Attempt to extract the container ID from the cgroup path
		container_id = get_container_id_from_cgroup_path(buffer);
		if (container_id != NULL)
		{
			// If a container ID is found, stop reading further
			break;
		}
	}

	fclose(fp);

	return container_id;
}

char *get_my_pod_name()
{
	FILE *file = fopen(POD_NAME_FILE, "r");
	if (file == NULL)
	{
		perror("Error opening pod name file");
		return NULL;
	}

	char *pod_name = (char *)malloc(256 * sizeof(char)); // Assuming maximum pod name length of 256 characters
	if (pod_name == NULL)
	{
		perror("Error allocating memory for pod name");
		fclose(file);
		return NULL;
	}

	if (fgets(pod_name, 256, file) == NULL)
	{
		perror("Error reading pod name from file");
		free(pod_name);
		fclose(file);
		return NULL;
	}

	// Remove trailing newline character if present
	char *newline = strchr(pod_name, '\n');
	if (newline != NULL)
	{
		*newline = '\0';
	}

	fclose(file);
	std::cout << "my pod name is " << pod_name << std::endl;
	return pod_name;
}

std::string get_container_id_from_kubernetes()
{
	// Read the pod name from /etc/hostname
	std::ifstream hostname_file("/etc/hostname");
	if (!hostname_file)
	{
		std::cerr << "Error: Unable to open /etc/hostname\n";
		return "";
	}
	std::string pod_name;
	std::getline(hostname_file, pod_name);
	hostname_file.close();

	// Read the service account token for authentication
	std::ifstream token_file("/var/run/secrets/kubernetes.io/serviceaccount/token");
	if (!token_file)
	{
		std::cerr << "Error: Unable to open Kubernetes service account token\n";
		return "";
	}
	std::string token;
	std::getline(token_file, token);
	token_file.close();

	// Construct the curl command
	std::string curl_cmd = "curl -s --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt "
												 "-H \"Authorization: Bearer " +
												 token + "\" "
																 "https://kubernetes.default.svc/api/v1/namespaces/default/pods/" +
												 pod_name;

	// Execute the curl command and capture output
	FILE *pipe = popen(curl_cmd.c_str(), "r");
	if (!pipe)
	{
		std::cerr << "Error: Failed to execute curl command\n";
		return "";
	}

	std::ostringstream result_stream;
	char buffer[1024];
	while (fgets(buffer, sizeof(buffer), pipe) != NULL)
	{
		result_stream << buffer;
	}
	pclose(pipe);

	std::string json_output = result_stream.str();
	std::cout << "got json output " << json_output << std::endl;

	// Parse JSON using nlohmann::json
	try
	{
		json pod_info = json::parse(json_output);
		if (pod_info.contains("status") && pod_info["status"].contains("containerStatuses"))
		{
			auto &container_statuses = pod_info["status"]["containerStatuses"];
			if (!container_statuses.empty() && container_statuses[0].contains("containerID"))
			{
				std::string container_id = container_statuses[0]["containerID"];
				if (container_id.find("docker://") == 0)
				{
					container_id = container_id.substr(9); // Remove "docker://"
				}
				return container_id;
			}
		}
		std::cerr << "Error: containerID not found in Kubernetes API response\n";
	}
	catch (json::parse_error &e)
	{
		std::cerr << "JSON Parsing Error: " << e.what() << '\n';
	}

	return "";
}

char *get_my_pod_node(apiClient_t *apiClient, const char *pod_name)
{

	char *node_name = NULL;
	char *pod_name_str = strdup(pod_name);	 // Convert const char * to non-const char *
	char *namespace_str = strdup("default"); // Convert const char * to non-const char *

	v1_pod_t *pod_info = CoreV1API_readNamespacedPod(apiClient, pod_name_str, namespace_str, NULL);

	free(pod_name_str);	 // Free memory allocated by strdup
	free(namespace_str); // Free memory allocated by strdup

	if (pod_info != NULL && pod_info->spec != NULL)
	{
		if (pod_info->spec->node_name != NULL)
		{
			node_name = strdup(pod_info->spec->node_name);
		}
		else
		{
			printf("Node name for pod '%s' is NULL.\n", pod_name);
		}
		v1_pod_free(pod_info);
	}
	else
	{
		printf("Failed to retrieve information for pod '%s'.\n", pod_name);
	}
	std::cout << "getting pod node " << node_name << std::endl;
	return node_name;
}

///////// GET INFO ABOUT CLUSTER ///////////////////////////////////////////////

std::string get_rootfs_path(const std::string &container_id)
{
	std::ifstream mountinfo("/hostproc/1/mountinfo"); // Use /hostproc instead of /proc
	std::string line;

	while (std::getline(mountinfo, line))
	{
		if (line.find(container_id) != std::string::npos)
		{
			std::stringstream ss(line);
			std::string field;
			std::vector<std::string> fields;

			while (ss >> field)
				fields.push_back(field);

			return fields[4]; // The mount point is the 4th field
		}
	}

	return "";
}

bool get_k8s_info(const std::string &rootfs, std::string &pod_name, std::string &image_name)
{
	std::ifstream config(rootfs + "/hostproc/run/containerd/io.containerd.runtime.v2.task/k8s.io/config.json");
	if (!config.is_open())
		return false;

	nlohmann::json j;
	config >> j;

	if (j.contains("annotations"))
	{
		pod_name = j["annotations"]["io.kubernetes.pod.name"].get<std::string>();
		image_name = j["annotations"]["io.kubernetes.container.image"].get<std::string>();
		return true;
	}

	return false;
}

apiClient_t *get_kube_api_client()
{
	char *basePath = NULL;
	sslConfig_t *sslConfig = NULL;
	list_t *apiKeys = NULL;
	int rc = load_incluster_config(&basePath, &sslConfig, &apiKeys);
	if (rc != 0)
	{
		printf("Cannot load kubernetes configuration in cluster.\n");
		return NULL;
	}
	apiClient_t *apiClient = apiClient_create_with_base_path(basePath, sslConfig, apiKeys);
	if (!apiClient)
	{
		printf("Cannot create a kubernetes client.\n");
		return NULL;
	}

	std::cout << "Got apiClient!" << std::endl;

	return apiClient;
}

void update_images_configmap()
{

	// Specify the namespace and name of the ConfigMap
	char *configMapName = strdup(CONFIGMAP_NAME);
#ifdef DEBUG
	std::cout << "Looking for configmap " << configMapName << std::endl;
#endif

	// Get the ConfigMap
	v1_config_map_t *configMapObj = CoreV1API_readNamespacedConfigMap(apiClient, configMapName, DEFAULT_NS, NULL);
	if (configMapObj)
	{
		if (configMapObj->data)
		{
#ifdef DEBUG
			std::cout << "Parsing ConfigMap data..." << std::endl;
#endif
			listEntry_t *entry;
			list_ForEach(entry, configMapObj->data)
			{
				v1_config_map_key_selector_t *data = (v1_config_map_key_selector_t *)entry->data;
				if (data)
				{
					// Split data by newline '\n'
					stringstream ss(data->name);
					string line;
					string appName = data->key; // App name is ConfigMap key
					string production;
					string oracle;
					string deployment;
					while (std::getline(ss, line, '\n'))
					{
						// Split each line by '='
						size_t delimiterPos = line.find('=');
						if (delimiterPos != std::string::npos)
						{
							deployment = data->key; // App name is ConfigMap key
							string label = line.substr(0, delimiterPos);
							string image = line.substr(delimiterPos + 1);
							if (production.empty())
							{
								production = image;
							}
							else
							{
								oracle = image;
							}
						}
					}

					// convert the production and oracles images to sha hashes
					string production_sha = getImageSHA(production);
					string oracle_sha = getImageSHA(oracle);

					// Print parsed key-value pair
					std ::cout << "Read CM entry! App name: " << appName << ", production: " << production << ", oracle: " << oracle << std::endl;
					std::cout << "Read CM entry! App name: " << appName << ", production sha: " << production_sha << ", oracle sha: " << oracle_sha << std::endl;
					image_pairs[production] = oracle;
					image_types[production] = PRODUCTION;
					image_types[oracle] = ORACLE;
					image_to_deployment[production] = deployment;
					image_to_deployment[oracle] = deployment;
					pair<string, string> image_pair(production, oracle);
					config_map[deployment] = image_pair;

					// update the sha to image name map
					sha_to_image_name_map[production_sha] = production;
					sha_to_image_name_map[oracle_sha] = oracle;
				}
			}
		}
		else
		{
			std::cout << "ConfigMap data is empty." << std::endl;
		}
		v1_config_map_free(configMapObj);
	}
	else
	{
		std::cout << "Failed to read ConfigMap." << std::endl;
	}

	// Cleanup
	free(configMapName);
	std::cout << "Finished reading ConfigMap." << std::endl;
}

v1_pod_t *get_matching_running_pod(string bad_pod_name)
{
	v1_pod_list_t *pod_list = NULL;
	pod_list = CoreV1API_listNamespacedPod(apiClient, DEFAULT_NS, /*namespace */
																				 NULL,									/* pretty */
																				 NULL,									/* allowWatchBookmarks */
																				 NULL,									/* continue */
																				 NULL,									/* fieldSelector */
																				 NULL,									/* labelSelector */
																				 NULL,									/* limit */
																				 NULL,									/* resourceVersion */
																				 NULL,									/* resourceVersionMatch */
																				 NULL,									/* sendInitialEvents */
																				 NULL,									/* timeoutSeconds */
																				 NULL										/* watch */
	);
	if (pod_list)
	{
		listEntry_t *listEntry = NULL;
		v1_pod_t *pod = NULL;
		list_ForEach(listEntry, pod_list->items)
		{
			pod = (v1_pod_t *)listEntry->data;
			string pod_name = pod->metadata->name;
			if (is_almost_equal(pod_name, bad_pod_name, 1))
			{
				return pod;
			}
		}
		v1_pod_list_free(pod_list);
		pod_list = NULL;
	}
	else
	{
		printf("Cannot get any pod.\n");
	}
	return NULL;
}

string get_deployment_from_pod(v1_pod_t *pod)
{

	// Extract labels from pod
	list_t *pod_labels = pod->metadata->labels;

	listEntry_t *pod_label_entry;
	list_ForEach(pod_label_entry, pod_labels)
	{
		keyValuePair_t *pod_label = (keyValuePair_t *)pod_label_entry->data;
		char *pod_label_key = (char *)pod_label->key;
		char *pod_label_value = (char *)pod_label->value;
		if (strcmp(pod_label_key, "app") == 0)
		{
#ifdef DEBUG
			std::cout << "found deployment " << pod_label_value << " for pod " << pod->metadata->name << std::endl;
#endif
			return pod_label_value;
		}
	}

	return "";
}

string get_production_from_oracle_image(string oracle_image)
{
	map<string, string>::iterator it;

	for (it = image_pairs.begin(); it != image_pairs.end(); it++)
	{
		if (it->second.compare(oracle_image) == 0)
		{
			return it->first;
		}
	}
	// Image not found in the images_configmap
	return "";
}

string get_opposite_image(string image)
{
	map<string, string>::iterator it;

	for (it = image_pairs.begin(); it != image_pairs.end(); it++)
	{
		if (it->first.compare(image) == 0)
			return it->second;
		else if (it->second.compare(image) == 0)
			return it->first;
	}
	// Image not found in the images_configmap
	return "";
}

void init_new_container_id(string container_id, string image_name, string pod_name)
{

	string image_name_corrected = image_name;
	char image_type = image_types[image_name_corrected];

	if (image_type == ORACLE)
	{
		time_t pod_start_time;
		time(&pod_start_time);
		oracle_containers_to_start_times[container_id] = pod_start_time;
	}

	container_types[container_id] = image_type;

	if (!image_type)
	{
		std::cout << "WARNING: container is not timelooping bc no image was found... image: " << image_name_corrected << std::endl;
		bpf_map_update_elem(container_types_map_fd, container_id.c_str(), &NOT_TIMELOOPING, BPF_ANY);
		return;
	}
#ifdef DEBUG
	std::cout << "  -- found a timelooping container " << container_id << std::endl;
	std::cout << "  -- image type is " << image_type << std::endl;
#endif

	// add container id to containers map
	bpf_map_update_elem(container_types_map_fd, container_id.c_str(), &image_type, BPF_ANY);

	int policy_id;
	string app_name = extract_app_name_from_pod(pod_name);
	if (policy_ids.find(app_name) == policy_ids.end())
	{
		// we do not have an image id for this app name
		// if we have not seen this image or its oracle, then we create a new image
		// id for it
		if (curr_num_timelooping_containers < MAX_TIMELOOPING_SERVICES)
		{
			policy_id = curr_num_timelooping_containers++;
			policy_ids[app_name] = policy_id;
		}
		else
		{
			std::cout << "WARNING: cannot timeloop bc we exceeded the num of timelooping containers " << app_name << std::endl;
			return;
		}
	}
	else
	{
		policy_id = policy_ids[app_name];
	}

	bpf_map_update_elem(container_ids_map_fd, container_id.c_str(), &policy_id, BPF_ANY);
	container_to_pod_map[container_id] = pod_name; // TODO: delete this line
	pod_to_container_map[pod_name] = container_id;
	container_to_image_map[container_id] = image_name_corrected;
	pair<string, string> new_image_container_pair(image_name_corrected, container_id);
	std::cout << "policy id is " << policy_id << " pod is " << pod_name << "app name is " << app_name << std::endl;
}

v1_pod_t *get_pod(char *pod_name)
{
	// Read the existing Pod
	v1_pod_t *pod = CoreV1API_readNamespacedPod(apiClient, pod_name, DEFAULT_NS, NULL);
	if (apiClient->response_code != 200 && apiClient->response_code != 201 && apiClient->response_code != 202)
	{
		return get_matching_running_pod(pod_name);
	}
	return pod;
}

void patch_deployment(string deployment_name, string new_image_name, bool select_node)
{

#ifdef DEBUG
	std::cout << "trying to patch deployment " << deployment_name << " to image " << new_image_name << " and to node " << my_node_name << std::endl;
#endif

	v1_deployment_t *deploy;
	object_t *body;
	char *name = strdup(deployment_name.c_str());
	char *new_image = strdup(new_image_name.c_str());

	cJSON *jsonArray = cJSON_CreateArray();
	cJSON *jsonImageObject = cJSON_CreateObject();
	cJSON_AddStringToObject(jsonImageObject, "op", "replace");
	cJSON_AddStringToObject(jsonImageObject, "path", "/spec/template/spec/containers/0/image");
	cJSON_AddStringToObject(jsonImageObject, "value", new_image);

	cJSON_AddItemToArray(jsonArray, jsonImageObject);
	// cJSON_Print(jsonImageObject);

	if (select_node)
	{
		cJSON *jsonNodeSelectorObject = cJSON_CreateObject();
		cJSON_AddStringToObject(jsonNodeSelectorObject, "op", "add"); // Use "add" operation
		cJSON_AddStringToObject(jsonNodeSelectorObject, "path", "/spec/template/spec/nodeSelector");

		cJSON *nodeSelector = cJSON_CreateObject();
		string hostname_str("kubernetes.io/hostname");
		cJSON_AddStringToObject(nodeSelector, hostname_str.c_str(), my_node_name.c_str());

		cJSON_AddItemToObject(jsonNodeSelectorObject, "value", nodeSelector);
		cJSON_AddItemToArray(jsonArray, jsonNodeSelectorObject);
	}

#ifdef DEBUG
	std::cout << "Converting json array to body " << std::endl;
#endif

	body = object_parseFromJSON(jsonArray);
	if (!body)
	{
		fprintf(stderr, "failed to convert patch to object\n");
		return;
	}

#ifdef DEBUG
	std::cout << "Going to do patch for name " << name << std::endl;
#endif

	deploy = AppsV1API_patchNamespacedDeployment(
			apiClient,
			name,
			DEFAULT_NS,
			body,
			NULL,
			NULL,
			NULL,
			NULL,
			0);

	printf("The return code of HTTP request=%ld\n", apiClient->response_code);

	free(name);
	free(new_image);
}

void delete_pod(v1_pod_t *pod)
{

	if (!pod || !pod->metadata || !pod->metadata->name)
	{
		std::cout << "No pod to delete." << std::endl;
		return;
	}

	if (!apiClient)
	{
		std::cerr << "Error: apiClient is null." << std::endl;
		return;
	}

	std::cout << "Deleting pod: " << pod->metadata->name << std::endl;

	// create delete options
	char *api_version = strdup("v1");
	char *kind = strdup("DeleteOptions");
	// create list_t for dry_run
	list_t *dry_run = list_createList();
	char *propagation_policy = strdup("Foreground");

	// Create preconditions (optional)
	v1_preconditions_t *preconditions = v1_preconditions_create(NULL, NULL);

	// Create DeleteOptions with necessary fields
	v1_delete_options_t *delete_options = v1_delete_options_create(
			api_version,			 // API version
			dry_run,					 // DryRun (NULL or list)
			0,								 // Grace period in seconds (0 for immediate delete)
			kind,							 // Kind (DeleteOptions)
			0,								 // OrphanDependents (deprecated, use propagationPolicy)
			preconditions,		 // Preconditions (NULL or valid preconditions)
			propagation_policy // PropagationPolicy (e.g., "Foreground", "Background", or "Orphan")
	);

	// Delete the existing pod after patching
	pod = CoreV1API_deleteNamespacedPod(
			apiClient,
			pod->metadata->name,
			"default",
			NULL,
			NULL,
			NULL,
			NULL,
			NULL,
			NULL);

	if (200 == apiClient->response_code || 202 == apiClient->response_code)
	{
		printf("The pod is deleted successfully.\n");
	}
	else
	{
		printf("Failed to delete the pod.\n");
	}
}

void print_node_selector(v1_pod_t *pod)
{
	if (pod == NULL || pod->spec == NULL || pod->spec->node_selector == NULL)
	{
		printf("Pod, Pod Spec, or Node Selector is NULL\n");
		return;
	}

	printf("Node Selector:\n");
	list_t *node_selector = pod->spec->node_selector; // Assuming node_selector is a list of key-value pairs

	// Iterate over the node_selector list
	listEntry_t *list_entry;
	list_ForEach(list_entry, node_selector)
	{
		keyValuePair_t *pair = (keyValuePair_t *)list_entry->data;
		if (pair != NULL)
		{
			printf("%s: %s\n", pair->key, (char *)pair->value);
		}
	}
}

std::string get_container_id_from_pod_name(std::string pod_name)
{
	return pod_to_container_map[pod_name];
}

void restart_container_with_new_image(string container_id)
{

	if (container_types[container_id] == DELETING)
	{
// we have already restarted this container with a new image, we ignore
// this event
#ifdef DEBUG
		std::cout << "we can ignore this event because it has already been previously deleted and patched" << std::endl;
#endif
		return;
	}

	string pod_name = container_to_pod_map[container_id];
	string image_name = container_to_image_map[container_id];
	string new_image_name = get_opposite_image(image_name);

	if (container_types[container_id] == ORACLE)
	{
		oracle_containers_to_start_times.erase(container_id);
	}

	if (new_image_name.empty())
	{
		std::cerr << "New image name is empty, cannot proceed." << std::endl;
		return;
	}

	// we mark this container as deleting so that we do not patch and restart
	// multiple times
	container_types[container_id] = DELETING;

	std::cout << "Preparing to restart container for pod " << pod_name << " with new image " << new_image_name << std::endl;

	// Read the existing Pod
	char *pod_name_s = strdup(pod_name.c_str());
	v1_pod_t *old_pod = get_pod(pod_name_s);
	if (!old_pod || !old_pod->spec || !old_pod->spec->containers)
	{
		std::cerr << "Failed to read pod information." << std::endl;
		// Don't forget to free dynamically allocated memory
		free(pod_name_s);
		return;
	}

	bool select_node = false;
	if (!old_pod->spec->node_selector)
		select_node = true;

	// string deployment = image_to_deployment[image_name];
	string deployment = get_deployment_from_pod(old_pod);
	patch_deployment(deployment, new_image_name, select_node);

	delete_pod(old_pod);
}

///////// ORCHESTRATE PODS /////////////////////////////////////////////////////

void do_timeloop(string container_id)
{
#ifdef DEBUG
	char container_type = container_types[container_id];
	std::cout << "doing timeloop for container " << container_id << " type " << container_type << std::endl;
#endif
	restart_container_with_new_image(container_id);
}

void check_for_overdue_oracles()
{
#ifdef DEBUG
	std::cout << "updating pods on node" << std::endl;
#endif

	time_t now;
	time(&now);

	v1_pod_list_t *pod_list = NULL;
	pod_list = CoreV1API_listNamespacedPod(apiClient, DEFAULT_NS, /*namespace */
																				 NULL,									/* pretty */
																				 NULL,									/* allowWatchBookmarks */
																				 NULL,									/* continue */
																				 NULL,									/* fieldSelector */
																				 NULL,									/* labelSelector */
																				 NULL,									/* limit */
																				 NULL,									/* resourceVersion */
																				 NULL,									/* resourceVersionMatch */
																				 NULL,									/* sendInitialEvents */
																				 NULL,									/* timeoutSeconds */
																				 NULL										/* watch */
	);

	if (pod_list)
	{

		listEntry_t *listEntry = NULL;
		v1_pod_t *pod = NULL;
		list_ForEach(listEntry, pod_list->items)
		{
			pod = (v1_pod_t *)listEntry->data;
			string pod_name = pod->metadata->name;

			if (strcmp(pod_name.c_str(), my_pod_name.c_str()) != 0 && pod->status && pod->status->phase && strcmp(pod->status->phase, "Running") == 0 && pod->spec && pod->spec->node_name && strcmp(pod->spec->node_name, my_node_name.c_str()) == 0)
			{
				if (pod_to_container_map.find(pod_name) == pod_to_container_map.end())
				{
					std::cout << "found a potentially overdue pod that is not familiar " << pod_name << std::endl;
				}
				string container_id = pod_to_container_map[pod_name];
				string image_name = container_to_image_map[container_id];

				if (image_types[image_name] == ORACLE && container_types[container_id] != DELETING && difftime(now, oracle_containers_to_start_times[container_id]) > ORACLE_TIMEOUT)
				{
					std::cout << "found an overdue pod!!!!! " << pod_name << std::endl;
					do_timeloop(container_id);
				}
			}
		}
		v1_pod_list_free(pod_list);
		pod_list = NULL;
	}
	else
	{
		printf("Cannot get any pod.\n");
	}
}

///////// HANDLE SYSTEM CALL EVENTS ////////////////////////////////////////////

std::string clean_container_id(const std::string &raw_id)
{
	const std::string prefix = "docker-";
	if (raw_id.find(prefix) == 0)
	{																				 // Check if the prefix exists at the start
		return raw_id.substr(prefix.length()); // Remove the prefix
	}
	// also check if prefix is cri-containerd-
	const std::string prefix2 = "cri-containerd-";
	if (raw_id.find(prefix2) == 0)
	{																					// Check if the prefix exists at the start
		return raw_id.substr(prefix2.length()); // Remove the prefix
	}
	return raw_id; // Return as is if prefix not found
}

/* All events passed to user space will be from policy violations, so first we
 * must determine if the violation is from a timelooping pod or not (all pods
 * running in the default NS are timelooping pods). If not a timelooping pod,
 * then update the containers BPF map so that we do not build a policy for it.
 * If the container is a timelooping pod, then we must start a timeloop or stop
 * a timeloop accordingly.
 */
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event_t *e = (event_t *)data;

	if (e->container_created)
	{

		char path[256], line[512];

		// Check if the process exists
		snprintf(path, sizeof(path), "/hostproc/%d/status", e->pid);
		if (access(path, F_OK) != 0)
		{
			return 0;
		}

		// Extract Container ID from /hostproc/<pid>/cgroup
		snprintf(path, sizeof(path), "/hostproc/%d/cgroup", e->pid);
		FILE *f = fopen(path, "r");
		if (!f)
		{
			std::cerr << "Failed to open cgroup file for PID: " << e->pid << std::endl;
			return 0;
		}

		char container_id[128] = {0};
		while (fgets(line, sizeof(line), f))
		{
			if (strstr(line, "docker") || strstr(line, "kubepods"))
			{
				char *id_start = strrchr(line, '/') + 1;
				char *dot = strchr(id_start, '.');
				if (dot)
					*dot = '\0'; // Trim ".scope"
				strncpy(container_id, id_start, sizeof(container_id) - 1);
				break;
			}
		}
		fclose(f);

		if (strlen(container_id) == 0 || strcmp(container_id, "cri-dockerd") == 0)
		{
			return 0;
		}

		// Extract Pod Name & Container Name from /hostproc/<pid>/mountinfo
		snprintf(path, sizeof(path), "/hostproc/%d/mountinfo", e->pid);
		f = fopen(path, "r");
		std::string pod_uid, container_name;
		if (f)
		{
			while (fgets(line, sizeof(line), f))
			{
				std::regex kubelet_pod_regex(R"(/kubelet/pods/([a-f0-9\-]+)/containers/([^/]+))");
				std::cmatch match;
				if (std::regex_search(line, match, kubelet_pod_regex))
				{
					pod_uid = match[1];
					container_name = match[2];
					break;
				}
			}
			fclose(f);
		}

		if (pod_uid.empty() || container_name.empty())
		{
			return 0;
		}

		// return if the pod name is "calico-node" or "kube-proxy"
		if (container_name == "calico-node" || container_name == "kube-proxy")
		{
			// std::cout << "Skipping calico-node or kube-proxy pod" << std::endl;
			return 0;
		}

		snprintf(path, sizeof(path), "/var/lib/containerd/%s/config.json", clean_container_id(container_id).c_str());

		std::ifstream file(path);
		if (!file.is_open())
		{
			std::cerr << "Failed to open Docker config for container ID: " << container_id << std::endl;
			return 0;
		}

		nlohmann::json config_json;
		string image_name;
		string pod_name;

		file >> config_json; // Parse JSON file

		// Extract pod name from annotations
		if (config_json.contains("annotations") &&
				config_json["annotations"].contains("io.kubernetes.cri.sandbox-name"))
		{
			pod_name = config_json["annotations"]["io.kubernetes.cri.sandbox-name"];
		}
		else
		{
			std::cerr << "Pod name not found in Docker config." << std::endl;
		}

		// Extract image name from annotations
		if (config_json.contains("annotations") &&
				config_json["annotations"].contains("io.kubernetes.cri.image-name"))
		{
			image_name = config_json["annotations"]["io.kubernetes.cri.image-name"];
		}
		else
		{
			std::cerr << "Image name not found in Docker config." << std::endl;
		}

		std::cout << "Event container created! Image Name: " << image_name
							<< ", Pod Name: " << pod_name
							<< ", Container ID: " << clean_container_id(container_id) << std::endl;

		init_new_container_id(clean_container_id(container_id), image_name, pod_name);
	}
	else
	{
		// timelooping event !
#ifdef DEBUG
		printCurrentTime();
		std::cout << e->syscall_num << ": " << e->policy_val << std::endl;
		std::cout << "container_id:" << e->container_id << std::endl;
#endif
		do_timeloop(e->container_id);
	}

	return 0;
}

int main(int argc, char **argv)
{
#ifdef DEBUG
	std::cout << "Debugging is enabled!" << std::endl;
#endif

	struct ring_buffer *rb = NULL;
	int err;

	curr_num_timelooping_containers = 0;

	my_container_id = get_container_id_from_kubernetes();
	if (my_container_id.empty())
	{
		fprintf(stderr, "Not running in a container\n");
		return 1;
	}

	my_pod_name = get_my_pod_name();
	if (my_pod_name.empty())
	{
		printf("Not able to get pod name\n");
		return 1;
	}

	apiClient = get_kube_api_client();
	if (!apiClient)
	{
		fprintf(stderr, "Failed to get Kubernetes API Client\n");
		return 1;
	}

	my_node_name = get_my_pod_node(apiClient, my_pod_name.c_str());

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Open BPF application */
	skel = timeloops_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	/* clear out policy table */
	for (int i = 0; i < MAX_TIMELOOPING_SERVICES; i++)
	{
		for (int j = 0; j < MAX_NUM_SYSCALLS; j++)
		{
			skel->bss->policy_table[i][j] = 0;
		}
	}

	/* Load & verify BPF programs */
	err = timeloops_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	container_types_map_fd = bpf_map__fd(skel->maps.container_types);
	container_ids_map_fd = bpf_map__fd(skel->maps.container_ids);

	bpf_map_update_elem(container_types_map_fd, my_container_id.c_str(), &NOT_TIMELOOPING, BPF_ANY);
	update_images_configmap();

	/* Attach tracepoint handler */
	err = timeloops_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
				 "to see output of the BPF programs.\n");
	time(&last_checked_oracles);
	time_t now;

	/* Process events */
	while (true)
	{

		time(&now);
		if (difftime(now, last_checked_oracles) > 10)
		{
#ifdef DEBUG
			std::cout << "checking for overdue oracles" << std::endl;
#endif
			check_for_overdue_oracles();
			time(&last_checked_oracles);
		}

		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	ring_buffer__free(rb);
	timeloops_bpf__destroy(skel);
	apiClient_free(apiClient);
	apiClient_unsetupGlobalEnv();
	return -err;
}
