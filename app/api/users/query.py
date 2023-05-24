checkEmail = """
select * from admin_users where email = "{email}";
"""

register_admin_user = """
insert into admin_users (admin_id, name, email, password, access_level,is_verified, company_name)
values ("{admin_id}", "{name}", "{email}", "{password}",
"{access_level}","{is_verified}", "{company_name}");
"""

addOtp = """
UPDATE admin_users set temp_code  = "{temp_code}" 
where 
email = "{email}";
"""

verifyAdmin = """
UPDATE admin_users set is_verified = "{is_verified}" 
where 
email = '{email}';
"""

adminResetPassword = """
UPDATE admin_users set password = "{password}" where email = "{email}";
"""

adminVerified = """
select * from admin_users where is_verified = 1 and access_level = 1
and email = "{admin_email}";
"""

userEmailExist = """
select * from users where email = "{email}";
"""

register_users = """
insert into users (user_id, name, email, password, access_level,is_verified, company_name, admin_id)
values ("{user_id}", "{name}", "{email}", "{password}",
"{access_level}","{is_verified}", "{company_name}", "{admin_id}");
"""

getAdminCompanyByID = """
select admin_users.company_name
from admin_users
inner join users on admin_users.admin_id = users.admin_id
where users.admin_id = '{admin_id}';
"""

getUserAccessLevelValue = """
select access_level.access_level_name
from access_level
inner join users on access_level.access_level_id =  access_level
where access_level = "{access_level}"; 
"""

userAddOtp = """
UPDATE users set temp_code  = "{temp_code}" 
where 
email = "{email}";
"""

verifyUser = """
UPDATE users set is_verified = "{is_verified}" 
where 
email = '{email}';
"""

updateUserPassword = """
UPDATE users set password = "{password}" 
where 
email = '{email}';
"""

checkUserIsVerified = """
select * from users where email = "{email}" and is_verified = 1;
"""

get_access_level = """
select * from access_level;
"""

admin_view_roles = """
select * from roles;
"""

admin_view_users = """
SELECT users.user_id , users.name , users.email , users.is_verified , users.company_name, 
admin_users.email as admin_email, admin_users.name as admin_name, users.is_banned,
users.created_at , access_level.access_level_name 
from users
inner join access_level on access_level.access_level_id = users.access_level 
left join admin_users on admin_users.admin_id = users.admin_id
WHERE users.company_name = "{company_name}"
and users.is_deleted = 0
order by created_at DESC;
"""

admin_view_admin_users = """
SELECT admin_users.admin_id,  admin_users.name , admin_users.email , admin_users.access_level ,
admin_users.is_verified , admin_users.company_name , admin_users.created_at 
from admin_users
inner join access_level on access_level.access_level_id = admin_users.access_level 
WHERE company_name = "{company_name}"
order by created_at DESC;
"""

update_users = """
UPDATE users set name = "{name}", access_level = '{access_level}', is_banned = "{is_banned}"
where user_id = '{user_id}' and company_name = '{company_name}';
"""

checkUserEmailById = """
select name,email,access_level,is_banned from users where user_id = "{user_id}";
"""

delete_users = """
UPDATE users set is_deleted = 1
where user_id = '{user_id}' and company_name = '{company_name}';
"""

create_project = """
insert into projects(project_id,project_name,project_description,project_url,user_id)
values("{project_id}", "{project_name}","{project_description}","{project_url}","{user_id}");
"""

create_project_users = """
insert into project_member(project_id,user_id,user_added)
values("{project_id}", "{user_id}","{user_added}");
"""

create_project_technology = """
insert into projects_technology (project_id,technology_id,user_added)
values("{project_id}", "{technology_id}","{user_added}");
"""

get_technology_details = """
select * from technology;
"""

get_project_details = """
SELECT projects.project_id , projects.project_name ,projects.project_description , projects.project_url,
projects.created_at ,admin_users.name at admin_name, admin_users.email as admin_created
from projects
left join admin_users on projects.admin_id = admin_users.admin_id 
where admin_users.company_name = "{company_name}"
order by projects.created_at DESC; 
"""

get_project_users = """
SELECT users.user_id, users.name , users.email, project_member.project_id, access_level.access_level_name
from project_member
left join users on project_member.user_id  = users.user_id 
left join access_level on access_level.access_level_id = users.access_level 
where project_member.project_id = "{project_id}"
order by project_member.created_at DESC; 
"""

get_project_technology = """
SELECT technology.technology_name, technology.id 
from technology
left join projects_technology on projects_technology.technology_id  = technology.id 
where projects_technology.project_id = "{project_id}"
order by projects_technology.created_at DESC;
"""

get_project_details_by_id = """
SELECT projects.project_id , projects.project_name ,projects.project_description , projects.project_url,
projects.created_at ,admin_users.name as admin_name, admin_users.email as admin_created, 
users.name as user_name, users.email as user_email
from projects
left join admin_users on projects.admin_id = admin_users.admin_id 
left join users on projects.user_id = users.user_id
where projects.project_id = "{project_id}"
order by projects.created_at DESC; 
"""

user_get_project_details = """
SELECT projects.project_id , projects.project_name ,projects.project_description , projects.project_url,
projects.created_at ,project_member.user_id, admin_users.name as admin_name, admin_users.email as admin_email,
users.name as user_name, users.email as user_email
from projects
inner join project_member on project_member.project_id  = projects.project_id 
left join admin_users on projects.admin_id = admin_users.admin_id 
left join users on projects.user_id = users.user_id
where project_member.user_id = '{user_id}'
order by projects.created_at DESC; 
"""

insertProjectMember = """
insert into project_member (user_id, project_id, user_added) 
values ("{user_id}", "{project_id}", "{user_added}");
"""

# get_project_details_users = """
# SELECT projects.project_id , projects.project_name ,projects.project_description , projects.project_url,
# projects.created_at ,users.name as created_by, users.email ,project_member.user_id
# from projects
# left join project_member on project_member.project_id  = projects.project_id
# left join users on projects.user_id = users.user_id
# where users.company_name = "{company_name}" and project_member.user_id = '{user_id}'
# order by projects.created_at DESC;
# """

checkProjectDetails = """
SELECT * from projects where project_id = '{project_id}';
"""

update_project_details = """
UPDATE projects set project_name = "{project_name}", 
project_description = "{project_description}",project_url= '{project_url}',
user_id = '{user_id}' where project_id = "{project_id}";
"""

remove_project_member = '''
DELETE from project_member WHERE user_id = '{user_id}' and project_id = '{project_id}';
'''

remove_project_technology = '''
DELETE from projects_technology  WHERE technology_id = '{technology_id}' and project_id = '{project_id}';
'''

adminInsertProjectRoles = """
insert into project_user_roles (project_id,user_id,role_id) values
("{project_id}", "{user_id}", "{role_id}");
"""

adminRemoveProjectRoles = """
DELETE from project_user_roles where role_id = "{role_id}" and project_id = "{project_id}" 
and user_id = "{user_id}"; 
"""

viewProjectUserRoles = """
SELECT project_user_roles.user_id , project_user_roles.role_id , project_user_roles.project_id,
roles.role_name, users.email 
from project_user_roles
inner join roles on project_user_roles.role_id = roles.role_id 
left join users on project_user_roles.user_id = users.user_id 
where project_user_roles.user_id = "{user_id}" and project_user_roles.project_id = "{project_id}";
"""

getUserProjectRoles = """
select * from project_user_roles where user_id = "{user_id}" and project_id = "{project_id}";
"""

getUserAccessLevel = """
select * from users where user_id = "{user_id}";
"""

insertEpic = """
insert into epic (epic_id,project_id,user_id,epic_subject,epic_description) values 
("{epic_id}","{project_id}","{user_id}","{epic_subject}","{epic_description}");
"""

updateEpic = """
update epic set epic_subject = "{epic_subject}", epic_description= "{epic_description}"
where epic_id = "{epic_id}";
"""

checkEpic = """
select epic.project_id , epic.user_id , epic.epic_subject , epic.epic_description from epic
where project_id = "{project_id}" and epic_id = "{epic_id}";
"""

viewEpic = """
select epic.project_id , epic.user_id , epic.epic_subject , epic.epic_description , epic.created_at ,
users.name as created_by, users.email as created_email, epic.epic_id, admin_users.email as admin_created,
admin_users.name as admin_name 
from epic 
left join users on epic.user_id = users.user_id 
left join admin_users on admin_users.admin_id = epic.admin_id
where project_id = "{project_id}";
"""

insertStory = """
insert into story (story_id,epic_id,project_id,user_id,story_subject,story_description) values 
("{story_id}","{epic_id}","{project_id}","{user_id}","{story_subject}","{story_description}");
"""

checkStory = """
select project_id , story_subject , story_description from story
where project_id = "{project_id}" and story_id = "{story_id}";
"""

updateStory = """
update story set story_subject = "{story_subject}", story_description = "{story_description}"
where story_id = "{story_id}";
"""

viewStory = """
select story.project_id , story.user_id , story.story_subject , story.story_id,
story.story_description , story.created_at , epic.epic_subject, epic.epic_description,
users.name as created_by, users.email as created_email, story.epic_id , admin_users.email as admin_created,
admin_users.name as admin_name
from story 
left join users on story.user_id = users.user_id 
left join epic on story.epic_id = epic.epic_id
left join admin_users on admin_users.admin_id = story.admin_id
where story.project_id = "{project_id}" and story.epic_id = "{epic_id}";
"""

insertTask = """
insert into tasks 
(tasks_id,story_id,project_id,user_id,task_subject,task_description,priority,status, user_assigned, estimated_time)
 values 
("{tasks_id}","{story_id}","{project_id}","{user_id}","{task_subject}",
"{task_description}","{priority}", "{status}", "{user_assigned}",  "{estimated_time}");
"""

checkTask = """
select project_id , task_subject , task_description, priority, status, user_assigned, admin_assigned,estimated_time
 from tasks
where project_id = "{project_id}" and tasks_id = "{tasks_id}";
"""

updateTask = """
update tasks set task_subject = "{task_subject}", task_description = "{task_description}",
priority = "{priority}", status = "{status}", user_assigned = "{user_assigned}", estimated_time = "{estimated_time}"
where tasks_id = "{tasks_id}";
"""

viewTasks = """
select tasks.project_id , tasks.task_subject , tasks.task_description , tasks.user_id , tasks.created_at , tasks.estimated_time,
tasks.updated_at, users.name as created_by, users.email as created_email, tasks.tasks_id, code_generation.code_id ,
admin_users.email as admin_created, admin_users.name as admin_name, tasks_status.status_type , tasks_priority.priority_type, 
u.name as user_assigned, au.name as admin_assigned,
u.email as user_assigned_email, au.email as admin_assigned_email,
tasks.user_assigned as tasks_user_id,
tasks.admin_assigned as tasks_admin_id
from tasks 
left join users on tasks.user_id = users.user_id 
left join code_generation on tasks.tasks_id = code_generation.tasks_id 
left join admin_users on tasks.admin_id = admin_users.admin_id
left join users as u on tasks.user_assigned = u.user_id
left join admin_users as au on tasks.admin_assigned = au.admin_id
left join tasks_status on tasks_status.id = tasks.status
left join tasks_priority on tasks.priority = tasks_priority.id 
where tasks.project_id = "{project_id}" and tasks.story_id = "{story_id}"
order by tasks.created_at DESC;
"""

viewTaskById = """
select tasks.project_id , tasks.task_subject , tasks.task_description , tasks.user_id , tasks.created_at ,tasks.estimated_time,
tasks.updated_at, users.name as created_by, users.email as created_email, tasks.tasks_id, code_generation.code_id ,
admin_users.email as admin_created, admin_users.name as admin_name, tasks_status.status_type , tasks_priority.priority_type, 
u.name as user_assigned, au.name as admin_assigned,
u.email as user_assigned_email, au.email as admin_assigned_email,
tasks.user_assigned as tasks_user_id,
tasks.admin_assigned as tasks_admin_id
from tasks 
left join users on tasks.user_id = users.user_id 
left join code_generation on tasks.tasks_id = code_generation.tasks_id 
left join admin_users on tasks.admin_id = admin_users.admin_id
left join users as u on tasks.user_assigned = u.user_id
left join admin_users as au on tasks.admin_assigned = au.admin_id
left join tasks_status on tasks_status.id = tasks.status
left join tasks_priority on tasks.priority = tasks_priority.id 
where tasks.tasks_id = "{tasks_id}"
order by tasks.created_at DESC;
"""

insertCodeData = """
insert into code_generation (code_id,project_id,tasks_id,code_query,code_response,user_id) values 
("{code_id}", "{project_id}", "{tasks_id}", "{code_query}", "{code_response}","{user_id}");
"""

viewCodeGen = """
SELECT * from code_generation 
where tasks_id = "{tasks_id}";
"""

updateCodeGen = """
UPDATE code_generation set code_query = "{code_query}", code_response = "{code_response}"
where code_id = "{code_id}";
"""

deleteStoryByID = """
DELETE from story WHERE project_id = '{project_id}' and story_id = "{story_id}";
"""

deleteStoryByTasksID = """
DELETE from tasks WHERE project_id = '{project_id}' and story_id = "{story_id}";
"""

deleteEpicByID = """
DELETE from epic WHERE project_id = '{project_id}' and epic_id = "{epic_id}";
"""

deleteStoryByEpicID = """
DELETE from story WHERE project_id = '{project_id}' and epic_id = "{epic_id}";
"""

deleteTasksByID = """
DELETE from tasks WHERE project_id = '{project_id}' and tasks_id = "{tasks_id}";
"""

insertTaskAssignee = """
insert into tasks_assigned (project_id, tasks_id, user_id)
values
("{project_id}", "{tasks_id}", "{user_id}");
"""

updateTaskAssignee = """
UPDATE tasks set user_assigned = "{user_assigned}", admin_assigned = Null
where tasks_id = "{tasks_id}";
"""

checkUserProjectMemberStatus = """
select user_id from project_member where user_id = "{user_id}" and project_id = "{project_id}";
"""

insertTaskStatusLog = """
insert into tasks_status_log (project_id, tasks_id, user_id , tasks_status)
values
("{project_id}", "{tasks_id}", "{user_id}", "{tasks_status}");
"""

getTasksStatus = """
select project_id,tasks_id,user_id,tasks_status from tasks_status where project_id = "{tasks_id}";
"""

updateTaskStatus = """
UPDATE tasks set status = "{status}"
where tasks_id = "{tasks_id}";
"""

insertProjectAttachment = """
insert into project_attachments (company_name, user_id,project_id,file_name,file_url,stored_file_name)
values ("{company_name}", "{user_id}", "{project_id}", "{file_name}", "{file_url}", "{stored_file_name}");
"""

deleteProjectAttachment = """
DELETE from project_attachments where stored_file_name = "{stored_file_name}";
"""

getProjectAttachment = """
SELECT * from project_attachments where project_id = "{project_id}";
"""

insertTaskAttachment = """
insert into tasks_attachments ( user_id, project_id,tasks_id,
file_name,file_url,stored_file_name)
values ("{user_id}", "{project_id}", "{tasks_id}","{file_name}", "{file_url}", "{stored_file_name}");
"""

deleteTaskAttachment = """
DELETE from tasks_attachments where stored_file_name = "{stored_file_name}";
"""

getTaskAttachment = """
SELECT * from tasks_attachments where tasks_id = "{tasks_id}";
"""

insertWorkLog = """
insert into tasks_work_log (user_id, project_id, tasks_id,
time_spent, log_description)
values ("{user_id}", "{project_id}", "{tasks_id}","{time_spent}", "{log_description}");
"""

checkWorkLog = """
SELECT time_spent,log_description from tasks_work_log where work_log_id  = "{work_log_id}";
"""

updateWorkLog = """
update tasks_work_log set time_spent = "{time_spent}", log_description = "{log_description}"
where work_log_id  = "{work_log_id}"
"""

checkTasksWorkLog = """
SELECT time_spent from tasks_work_log where tasks_id  = "{tasks_id}";
"""

checkTaskByUser = """
SELECT tasks_work_log.created_at,tasks_work_log.time_spent,tasks_work_log.log_description, users.name,users.email,
tasks_work_log.user_id, tasks_work_log.work_log_id
from tasks_work_log 
left join users on users.user_id =  tasks_work_log.user_id
where tasks_work_log.tasks_id = "{tasks_id}" order by created_at DESC;
"""

checkTaskByUserID = """
SELECT tasks_work_log.created_at,tasks_work_log.time_spent,tasks_work_log.log_description, users.name,users.email,
tasks_work_log.user_id
from tasks_work_log 
left join users on users.user_id =  tasks_work_log.user_id
where tasks_work_log.tasks_id = "{tasks_id}" and tasks_work_log.user_id = "{user_id}" order by created_at DESC;
"""

insertManagerComment = """
insert into tasks_comment (user_id, project_id, tasks_id, manager_comment)
values ("{user_id}", "{project_id}", "{tasks_id}","{manager_comment}");
"""

insertUserComment = """
insert into tasks_comment (user_id, project_id, tasks_id, user_comment)
values ("{user_id}", "{project_id}", "{tasks_id}","{user_comment}");
"""

updateManagerComment = """
UPDATE tasks_comment set manager_comment = "{manager_comment}"
where comment_id = "{comment_id}";
"""

updateUserComment = """
UPDATE tasks_comment set user_comment = "{user_comment}"
where comment_id = "{comment_id}";
"""

deleteComment = """
DELETE from tasks_comment where comment_id = "{comment_id}";
"""

checkUserComment = """
select comment_id,user_id from tasks_comment where comment_id = "{comment_id}";
"""

viewComment = """
select tasks_comment.user_id ,tasks_comment.user_comment ,tasks_comment.manager_comment ,tasks_comment.created_at ,
users.name , users.email , tasks_comment.updated_at, tasks_comment.comment_id,
admin_users.name as admin_name, admin_users.email as admin_email
from tasks_comment
left join users on tasks_comment.user_id = users.user_id 
left join admin_users on tasks_comment.admin_id = admin_users.admin_id
where tasks_id = "{tasks_id}" order by tasks_comment.created_at DESC;
"""

checkTasksAssignedLog = """
SELECT users.name as user_name, users.email as user_email,admin_users.name  as admin_name, 
admin_users.email as admin_email, tasks_assigned.user_id, tasks_assigned.admin_id , tasks_assigned.created_at ,
tasks_assigned.updated_at 
from tasks_assigned
left join users on users.user_id = tasks_assigned.user_id 
left join admin_users  on admin_users.admin_id  = tasks_assigned.admin_id 
where tasks_assigned.tasks_id = "{tasks_id}"
order by tasks_assigned.created_at DESC ;
"""

checkTaskStatusLog = """
SELECT users.name as user_name, users.email as user_email , tasks_status.status_type , tasks_status_log.created_at , 
tasks_status_log.updated_at ,admin_users.name  as admin_name, admin_users.email as admin_email
from tasks_status_log
left join users on users.user_id = tasks_status_log.user_id 
left join admin_users  on admin_users.admin_id  = tasks_status_log.admin_id 
LEFT JOIN tasks_status on tasks_status.id = tasks_status_log.tasks_status 
where tasks_status_log.tasks_id = "{tasks_id}"
order by tasks_status_log.created_at DESC ;
"""

checkProjectMembers = """
SELECT * from project_member where user_id = '{user_id}' and 
project_id = '{project_id}';
"""

totalProjectMember = """
SELECT COUNT(*) as total_member from project_member where project_id = '{project_id}' 
"""

totalProjectTechnologies = """
SELECT COUNT(*) as  project_technology from projects_technology where project_id = '{project_id}' ;
"""

totalTimeOnProject = """
SELECT time_spent from tasks_work_log where project_id  = "{project_id}";
"""

totalProjectCodeGenerated = """
SELECT COUNT(*) as code_generated  from code_generation where project_id  = "{project_id}";
"""

totalProjectEpic = """
SELECT COUNT(*) as total_epic from epic where project_id  = "{project_id}";
"""

totalProjectStory = """
SELECT COUNT(*) as total_story from epic where project_id  = "{project_id}";
"""

totalProjectTask = """
SELECT COUNT(*) as total_tasks from tasks where project_id  = "{project_id}";
"""

status_open = """
SELECT COUNT(*) as status_open from tasks where 
project_id  = "{project_id}" and status = '1';
"""

status_backlog = """
SELECT COUNT(*) as status_backlog from tasks where 
project_id  = "{project_id}" and status = '2';
"""

status_to_do = """
SELECT COUNT(*) as status_to_do from tasks where 
project_id  = "{project_id}" and status = '3';
"""

status_under_review = """
SELECT COUNT(*) as status_under_review from tasks where 
project_id  = "{project_id}" and status = '4';
"""

status_in_progress = """
SELECT COUNT(*) as status_in_progress from tasks where 
project_id  ="{project_id}" and status = '5';
"""

status_ready_for_qa = """
SELECT COUNT(*) as status_ready_for_qa from tasks where 
project_id  = "{project_id}" and status = '6';
"""

status_qa_in_progress = """
SELECT COUNT(*) as status_qa_in_progress from tasks where 
project_id  = "{project_id}" and status = '7';
"""

status_qa_passed = """
SELECT COUNT(*) as status_qa_passed from tasks where 
project_id  = "{project_id}" and status = '8';
"""

status_blocked = """
SELECT COUNT(*) as status_blocked from tasks where 
project_id  = "{project_id}" and status = '9';
"""

status_done = """
SELECT COUNT(*) as status_done from tasks where 
project_id  = "{project_id}" and status = '10';
"""

viewTasksListByStatus = """
select tasks.tasks_id, tasks.task_subject , tasks.task_description , tasks_status.status_type  ,
tasks.created_at , tasks.updated_at , story.story_subject
from tasks
left join tasks_status on tasks_status.id = tasks.status 
left join story on story.story_id = tasks.story_id 
WHERE tasks.project_id = "{project_id}" and tasks.status = "{status}"
ORDER BY tasks.created_at DESC;
"""