# Degree Audit API — degreeaudit.yale.edu

All endpoints require session cookie (`JSESSIONID` etc.) from an authenticated browser session.
Base: `https://degreeaudit.yale.edu/responsive/api`

---

## User Identity
**Endpoint:** `GET /api/users/myself`

| Data | Field |
|------|-------|
| Student ID | `id` / `userId` |
| Full name | `name` |
| First/last name | `firstName`, `lastName` |
| User class (student/advisor) | `userClass` |
| Permitted actions | `keys[]` (e.g. SDWEB31, SDWHATIF, SDAUDPDF) |

---

## Degree Audit
**Endpoint:** `GET /api/audit?studentId=&school=UG&degree=BA&is-process-new=false&audit-type=AA&auditId=&include-inprogress=true&include-preregistered=true&aid-term=`
**Accept header:** `application/vnd.net.hedtech.degreeworks.dashboard.audit.v1+json`

### auditHeader
| Data | Field |
|------|-------|
| Overall % complete | `percentComplete` |
| GPA (student system) | `studentSystemGpa` |
| GPA (DegreeWorks) | `degreeworksGpa` |
| Audit date | `dateYear`, `dateMonth`, `dateDay` |
| Credits applied (resident) | `residentApplied` |
| Credits in progress | `residentAppliedInProgress` |
| Transfer credits | `transferApplied` |
| Exam credits (AP/IB) | `examAppliedCredits` |
| Freeze status | `freezeType`, `freezeTypeDescription`, `freezeDate` |

### degreeInformation.degreeDataArray[0]
| Data | Field |
|------|-------|
| Degree (BA/BS) | `degree`, `degreeLiteral` |
| School | `school`, `schoolLiteral` |
| Catalog year | `catalogYear`, `catalogYearLit` |
| Active term | `activeTerm`, `activeTermLiteral` |
| Expected graduation term | `degreeTerm` |
| Class year | `studentLevelLiteral` |
| Cumulative GPA | `studentSystemCumulativeGpa` |
| Credits earned | `studentSystemCumulativeTotalCreditsEarned` |

### degreeInformation.goalArray
| Data | Filter by `code` |
|------|-------|
| College (e.g. Yale College) | `code === "COLLEGE"` → `valueLiteral` |
| Major | `code === "MAJOR"` → `valueLiteral` |
| Residential college advisor | `code === "ADVISOR"`, `attachCode === "RCD"` → `advisorName`, `advisorEmail` |
| Academic advisor | `code === "ADVISOR"`, `attachCode === "RCAA"` → `advisorName`, `advisorEmail` |
| DUS / faculty advisor | `code === "ADVISOR"`, `attachCode === "UCCA"` → `advisorName`, `advisorEmail` |

### blockArray
Each block = one requirement group (e.g. "Distributional Requirements for Freshman Year").

| Data | Field |
|------|-------|
| Block title | `title` |
| % complete | `percentComplete` |
| Credits applied | `creditsApplied` |
| GPA for block | `gpa` |
| Individual rules | `ruleArray[]` (recursive — rules contain `ruleArray`) |

**Rule fields:**
| Data | Field |
|------|-------|
| Requirement label | `label` |
| Rule type | `ruleType` (Course, Group, IfElse, etc.) |
| % complete | `percentComplete` |
| Complete flag | `requirement.ruleComplete` |
| Credits required | `requirement.creditsBegin` |
| Nested rules | `ruleArray[]` |

### classInformation.classArray
All courses on the student's record (completed + in-progress).

| Data | Field |
|------|-------|
| Department / number | `discipline`, `number` |
| Course title | `courseTitle` |
| Credits | `credits` |
| Letter grade | `letterGrade` |
| Term | `term`, `termLiteral` |
| In progress | `inProgress` ("Y"/"N") |
| Pass/fail | `passfail` ("Y"/"N") |
| Status | `status` ("A" = applied, etc.) |
| Distributional attributes | `attributeArray[]` → filter `code === "ATTRIBUTE"` → `value` (e.g. YCQR, YCWR, YCSC) |
| Which requirements satisfied | `locArray[]` → `requirementId`, `nodeLocation` |
| Repeat policy | `repeatPolicy`, `repeatDiscipline`, `repeatNumber` |
| Transfer course | `transfer`, `transferCode` |

**Common attribute codes:**
| Code | Meaning |
|------|---------|
| YCQR | Quantitative Reasoning |
| YCWR | Writing |
| YCSC | Sciences |
| YCSH | Sciences with lab |
| YCSO | Social Sciences |
| YCHU | Humanities |
| YCLA | Languages |

---

## Potential Future Features

| Feature | Where to get data |
|---------|-------------------|
| Advisor contact info | `degreeInformation.goalArray` filtered by `code === "ADVISOR"` |
| Expected graduation date | `degreeInformation.degreeDataArray[0].degreeTerm` |
| Class year | `degreeInformation.degreeDataArray[0].studentLevelLiteral` |
| AP/IB exam credits | `auditHeader.examAppliedCredits` |
| Transfer credits | `auditHeader.transferApplied` |
| What-if audit (hypothetical major) | Same `/api/audit` endpoint with `audit-type=WI&is-process-new=true` and major params |
| PDF export | Key `SDAUDPDF` in `users/myself` keys — likely a separate endpoint |
| Double major audit | Worksheet type `WEB32` instead of `WEB31` |
| Major-specific requirements | `blockArray` entry where `title` matches major name |
| Courses satisfying a specific distributional req | `classArray` filtered by `attributeArray[].value === "YCQR"` etc. |
| Insufficient/failed courses | `classInformation` → `reasonInsufficient`, `forceInsufficient` fields |
| In-progress courses | `classArray` filtered by `inProgress === "Y"` |
| Pre-registered courses | `classArray` filtered by `preregistered === "Y"` |
