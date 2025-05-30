Immutable Storage Management
============================

Nexoedge supports immutable storage management which denies unwanted user access, including reads, modifications, and deletion, on specified objects.
Authorized administrators can set per-object policies to specify the period and scope of access restrictions.

In particular, the design follows the recommendations in ISO/TS 18759:2022 (e.g., Section 5 and 6) on immutable storage management, which can be utilized as a part of counter measures against cyber-attacks, as well as fulfilling data storage compliance requirements, e.g., retention periods in data archives. 

Overview
--------

Immutability Policies
+++++++++++++++++++++

To enforce per-object policy-based storage immutability in Nexoedge, administrators can apply the following four types of *states/holds* to each data object.

* **Immutable state**: When an object is in an valid immutable period, it cannot be modified or deleted.
* **Modification hold**: When an object has a valid modification hold, it cannot be modified.
* **Deletion hold**: When an object has a valid deletion hold, it cannot be deleted.
* **Access hold**: When an object has a valid access hold, all types of data access operations including reads are denied.

Each state and hold comes with a definite **valid period** measured in days. The start and end time of any hold or state is always 00:00:00 UTC and 23:59:59 UTC, respectively. Valid periods always last one day or more and can never be shortened. When the valid period of a state or hold is over, the state or hold is said to be expired. To set an indefinite valid period, a state or hold can be set to automatically renew.

Note that immutability policies do not enforce automatic deletion of objects with expired immutability or deletion hold. Such maintenance operations are separately handled and governed by data lifecycle management policies.

Policy Management
+++++++++++++++++

To control the immutability policies for each data object, administrators set and update the policies via a set of APIs that is independent of data operations. Authentication of the set of APIs is also separate from that of the data operations.

Design
------

The model of per-object immutable policies and their enforcement and management are detailed as follows.

Policy State
++++++++++++

Extra metadata is used to record the policy state applied to a data object in Nexoedge. Below are the attributes of a generic policy.

* Type of the policy, either immutability, modification hold, deletion hold, and access hold
* Start date in UTC time
* Valid period in number of days from the start date
* Whether the policy renews (i.e., extends indefinitely) by itself

Each data object can have at most four policies attached. A policy attached is valid (or expired) if it is within (or beyond) the valid period.
Note that under data object copy operations, the copied data object does not inherit any policies attached to the source data object.

Policy Enforcement
++++++++++++++++++

Nexoedge always enforces per-object immutability policies at the start of each per-object write/update, read and deletion operation flow, via the following checks:

* Write/Update: Check for the immutable state, modification-hold, and access-hold. If any of them is valid, deny the operation.
* Read: Check for the access-hold. If the hold is valid, deny the operation.
* Delete: Check for the immutable state, deletion-hold, and access-hold. If any of them is valid, deny the operation.
* Rename: Check for the immutable state, modification-hold, deletion-hold, and access-hold. If any of them is valid, deny the operation.
* Copy: Check for the access-hold. If it is valid, deny the operation.

Policy Management
+++++++++++++++++

Nexoedge allows policy management including policy attachment and updates via the following set of controls over APIs.

* Policy attachment: Attach a new policy to a specific object
* Policy updates: Update the existing policy of a specific object

Note that policy updates only apply to existing policies (regardless of the states of validity) and can only extend (but never shorten) the policies’ valid periods.

These APIs require authorization. To access these APIs, administrators need to obtain an authentication token to authenticate themselves. Authentication tokens are set to expire after one hour of its generation. These tokens are self-described with the expiration date and administrator user identifier embedded to minimize server-side resources (e.g., compute and storage) for token tracking. They are also verifiable.

Below is a brief API specification for policy management.

Policy Management APIs (policy adjustment)

===============================     ================================================================================    ======================================
Management Ops.                     Input                                                                               Output
===============================     ================================================================================    ======================================
Obtain an authentication token      Username; Password                                                                  Authentication token
Attach a policy                     Authentication token, data object name, all policy attributes                       Attachment result: succeeded or failed
Adjust policy renewal               Authentication token, data object name, whether to enable or disable the renewal    Adjustment result: succeeded or failed
Extend a policy                     Authentication token, data object name, all policy attributes                       Adjustment result: succeeded or failed
===============================     ================================================================================    ======================================

Besides, Nexoedge supports a few APIs for enquiring the existing policies of a data object.

====================================================================    ==================================================================    ===================================================================================
Enquiry Operations                                                      Input                                                                 Output                                                      
====================================================================    ==================================================================    ===================================================================================
Obtain all attributes of a specific type of policy of an data object    Authentication token, data object name, type of policy to enquiry     All policy attributes if the policy exists; Empty otherwise.
Obtain all attributes of all policy of an data object                   Authentication token, data object name                                A list of the following per policy type: all policy attributes if the policy exists
====================================================================    ==================================================================    ===================================================================================


Implementation
--------------

Below is a summary of remarks on key implementation details and limitations.

Policy States
+++++++++++++

Each policy state is persisted in the Nexoedge metadata store as a ‘hash’ which is a collection of key-value pairs under a hash key.
Nexoedge embeds the type of the policy into the hash key which also contains the data object identifier, such that the key is deterministic.
Nexoedge also stores each of the remaining policy attributes (i.e., policy start date, valid period, and renewal state) as a field-value pair in the value.
This schema allows a quick existence check and retrieval of a given type of policy for a data object.
Below are the known limitations on the policy attributes.

* Policy start date: ‘time_t’ is used to represent the time. ‘time_t’ is known to be vulnerable to the ‘2038 problem’ on 32-bit operating systems. Using 64-bit systems over 32-bit to mitigate the issue is strongly recommended. There is also an underlying assumption that no policy starts from the Epoch and any start date at the Epoch is regarded as invalid.

* Valid period: To balance between usability and memory efficiency, the supported maximum number of days is 32767 (roughly 89 years). While it is sufficient for most use cases, it can be adjusted to a longer period upon request to our technical team.

Policy Enforcement
++++++++++++++++++

The checking on the existence and validity of policies is done via a successful query of the deterministic key constructed from the policy type and data object identifier, followed by comparing the valid period and the “current time”.

Policy Management
+++++++++++++++++

Overall, Nexoedge provides the APIs over a RESTful (i.e., web-based) interface with support of SSL/TLS to ensure data-in-transit security. 
Inputs of the APIs are in the HTTP request headers and bodies, while the outputs are in HTTP response bodies.
All data in the HTTP request and response bodies are encoded in JSON format.
Authentication tokens are implemented as JSON web tokens (JWT) and utilize a secret vault for authentication credentials.
The current implementation supports LDAP for authentication credential management.
For the detailed API specification, refer to the OpenAPI specification on GitHub.

Action Log
++++++++++

For traceability, Nexoedge records all policy management and enforcement actions in its log file.
