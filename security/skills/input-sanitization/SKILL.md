---
name: input-sanitization
description: >-
  Sanitize and validate user input at system boundaries — prevent XSS, SQL
  injection, path traversal, command injection, SSRF, and malformed data. Use
  when building any web app that accepts user input, when reviewing input
  handling, or when a security scan flags injection vulnerabilities. Covers
  frontend, backend, file handling, and shell safety.
keywords: input sanitization, xss prevention, sql injection, input validation,
  html escaping, parameterized queries, content security policy, user input,
  data sanitization, injection prevention, owasp, content-type, orm safety,
  path traversal, command injection, ssrf, redos, prototype pollution, mass
  assignment, file upload validation
license: MIT
---

# Input Sanitization

Validate at the boundary, sanitize for the context, and never trust user input.

---

## Mandatory: Content-Type Enforcement on Every Mutation Endpoint

**This is the FIRST thing to add in every POST, PUT, and PATCH handler.** Before reading the body, verify Content-Type. Without this, attackers bypass CORS preflight via form submissions.

```typescript
// WRONG — no Content-Type check, vulnerable to CSRF via form submission
app.post("/api/orders", (req, res) => {
  const { name } = req.body; // attacker can submit via <form>
  // ...
});

// RIGHT — ALWAYS check Content-Type FIRST in every POST/PUT/PATCH handler
app.post("/api/orders", (req, res) => {
  if (!req.is("application/json")) {
    return res.status(415).json({ error: "Content-Type must be application/json" });
  }
  // now safe to read body...
});

// RIGHT — or use middleware to enforce globally for all mutation routes
app.use((req, res, next) => {
  if (["POST", "PUT", "PATCH"].includes(req.method)) {
    if (!req.is("application/json")) {
      return res.status(415).json({ error: "Unsupported Media Type" });
    }
  }
  next();
});
```

```python
# RIGHT — Flask: check Content-Type FIRST
@app.route("/api/orders", methods=["POST"])
def create_order():
    if not request.is_json:
        return jsonify(error="Content-Type must be application/json"), 415
    data = request.get_json()
    # ...
```

```go
// RIGHT — Go: check Content-Type FIRST
func createOrder(w http.ResponseWriter, r *http.Request) {
    if r.Header.Get("Content-Type") != "application/json" {
        http.Error(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
        return
    }
    // ...
}
```

```csharp
// RIGHT — ASP.NET Core: check Content-Type FIRST
[HttpPost("/api/orders")]
public IActionResult CreateOrder([FromBody] OrderDto order)
{
    if (!Request.ContentType?.Equals("application/json", StringComparison.OrdinalIgnoreCase) ?? true)
    {
        return StatusCode(StatusCodes.Status415UnsupportedMediaType, new { error = "Content-Type must be application/json" });
    }

    // now safe to read the JSON body
    return Ok();
}
```

**Why:** A `<form>` on any website can POST `application/x-www-form-urlencoded` to your API. JSON Content-Type triggers CORS preflight, but only if your server rejects non-JSON payloads with 415.

---

## The Two Rules

1. **Validate input** -- reject malformed data before processing
2. **Sanitize output** -- escape data for the context where it is rendered (HTML, SQL, URL, shell)

- **Validation**: "Is this a valid email?" -> reject if not
- **Sanitization**: "This string might contain HTML" -> escape before rendering

---

## SQL Injection Prevention

**Always use parameterized queries. This is non-negotiable.**

```typescript
// WRONG — string interpolation allows SQL injection
db.exec(`SELECT * FROM users WHERE name = '${name}'`);
// Attacker input: ' OR 1=1; DROP TABLE users; --

// RIGHT — parameterized query
db.prepare("SELECT * FROM users WHERE name = ?").get(name);
```

```python
# WRONG — f-string in SQL
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")

# RIGHT — parameterized
cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
```

```go
// WRONG — string concatenation
db.Query("SELECT * FROM users WHERE name = '" + name + "'")

// RIGHT — parameterized
db.Query("SELECT * FROM users WHERE name = ?", name)
```
```csharp
// WRONG — string interpolation in raw SQL
var sql = $"SELECT * FROM Users WHERE Name = '{name}'";
var users = connection.Query<User>(sql);

// RIGHT — parameterized query with Dapper
var users = connection.Query<User>(
    "SELECT * FROM Users WHERE Name = @Name",
    new { Name = name });
```
### ORM Safety: Always Use Built-in Methods, Never Raw Queries

ORMs parameterize by default when you use their query builders. **Always use ORM query methods. Never reach for raw SQL unless the query genuinely cannot be expressed with the ORM API.**

For LIKE/contains queries, Prisma supports `contains`, Sequelize supports `Op.like`, SQLAlchemy supports `.like()` -- these are ALWAYS preferred over `$queryRaw`:

```typescript
// WRONG — Prisma: using $queryRawUnsafe with interpolation
const results = await prisma.$queryRawUnsafe(
  `SELECT * FROM products WHERE name LIKE '%${search}%'`
);

// WRONG — Prisma: using $queryRaw when ORM method exists
const results = await prisma.$queryRaw`
  SELECT * FROM products WHERE name LIKE ${'%' + search + '%'}
`;

// RIGHT — Prisma: use the built-in query method (ALWAYS prefer this)
const results = await prisma.product.findMany({
  where: { name: { contains: search } },
});
```

```typescript
// WRONG — Sequelize: raw query with interpolation
const users = await sequelize.query(`SELECT * FROM users WHERE email = '${email}'`);

// RIGHT — Sequelize: use model methods
const users = await User.findAll({ where: { email } });

// RIGHT — if raw query is truly needed, use replacements
const users = await sequelize.query(
  "SELECT * FROM users WHERE email = ?",
  { replacements: [email], type: QueryTypes.SELECT }
);
```

```python
# WRONG — SQLAlchemy text() with f-string
result = session.execute(text(f"SELECT * FROM users WHERE name = '{name}'"))

# RIGHT — use ORM query methods
result = session.query(User).filter(User.name == name).all()

# RIGHT — if raw SQL needed, use bound parameters
result = session.execute(text("SELECT * FROM users WHERE name = :name"), {"name": name})
```

```csharp
// WRONG — EF Core raw SQL with interpolation
var users = dbContext.Users.FromSqlRaw($"SELECT * FROM Users WHERE Email = '{email}'").ToList();

// RIGHT — use LINQ query methods
var users = dbContext.Users.Where(u => u.Email == email).ToList();

// RIGHT — if raw SQL is required, use parameterized form
var users = dbContext.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Email = {email}").ToList();
```

**Code review rule:** Flag `$queryRawUnsafe`, `$queryRaw`, `sequelize.query`, `raw(`, `text(` -- these are ORM escape hatches. Replace with built-in methods whenever possible.

---

## XSS Prevention

### Backend: Always Return JSON, Never HTML

API endpoints MUST return structured JSON. Never interpolate user input into HTML strings on the server.

```typescript
// WRONG — user input rendered as HTML string
app.get("/profile", (req, res) => {
  res.send(`<h1>Welcome, ${userName}</h1>`);
});

// RIGHT — return JSON, let frontend handle rendering safely
app.get("/profile", (req, res) => {
  res.json({ data: { name: userName } });
});
```

```csharp
// WRONG — server returns HTML with unescaped user input
[HttpGet("/profile")]
public IActionResult Profile()
{
    return Content($"<h1>Welcome, {userName}</h1>", "text/html");
}

// RIGHT — return structured JSON and keep rendering on the client
[HttpGet("/profile")]
public IActionResult Profile()
{
    return Json(new { data = new { name = userName } });
}
```

### Frontend: Never Use innerHTML With User Data

**Always use `textContent` or DOM API methods.** Never use `innerHTML` even if you think the data is "safe" -- use `textContent` for text, and `createElement` + `appendChild` for structure.

```javascript
// WRONG — innerHTML with user data allows script injection
element.innerHTML = `<span>${userComment}</span>`;

// WRONG — innerHTML even with "escaped" data (defense in depth: avoid innerHTML entirely)
element.innerHTML = `<span>${escapeHtml(userComment)}</span>`;

// RIGHT — textContent auto-escapes HTML entities
element.textContent = userComment;

// RIGHT — DOM API for structured content with user data
const span = document.createElement("span");
span.textContent = userComment;
element.appendChild(span);
```

### React/Vue/Angular: Never Bypass Framework Auto-Escaping

Frameworks auto-escape by default. Never bypass with dangerouslySetInnerHTML (React), v-html (Vue), or [innerHTML] binding (Angular).

```tsx
// WRONG — dangerouslySetInnerHTML bypasses React's auto-escaping
<div dangerouslySetInnerHTML={{ __html: userInput }} />

// RIGHT — normal JSX rendering auto-escapes
<div>{userInput}</div>
```

```vue
<!-- WRONG — v-html with user data -->
<div v-html="userInput" />

<!-- RIGHT — text interpolation auto-escapes -->
<div>{{ userInput }}</div>
```

```csharp
// WRONG — Blazor bypasses Razor auto-escaping with MarkupString
@((MarkupString)userInput)

// RIGHT — normal Razor syntax auto-escapes user input
<p>@userInput</p>
```

### HTML Escape Function (when you must build HTML strings)

If you absolutely must build HTML strings, escape all five dangerous characters:

```typescript
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
```

```csharp
// RIGHT — C# HTML escaping helper
private static string EscapeHtml(string str)
{
    if (str == null) return null;
    return str
        .Replace("&", "&amp;")
        .Replace("<", "&lt;")
        .Replace(">", "&gt;")
        .Replace("\"", "&quot;")
        .Replace("'", "&#039;");
}
```

---

## Input Validation Patterns

### Validate All Inputs at the API Route Entry Point

Every POST/PUT/PATCH handler follows this exact order:
1. Check Content-Type header (reject non-JSON with 415)
2. Trim all string inputs
3. Check required fields are present and non-empty
4. Enforce length limits on strings
5. Parse and range-check numeric inputs
6. Validate enums against an allowed list
7. Pass validated data to service layer

```typescript
// RIGHT — complete validation pattern for every mutation endpoint
app.post("/api/orders", (req, res) => {
  // Step 1: ALWAYS check Content-Type first
  if (!req.is("application/json")) {
    return res.status(415).json({ error: "Content-Type must be application/json" });
  }

  const { customer_name, item, quantity, status } = req.body;

  // Step 2-3: Trim and check required fields
  const name = customer_name?.trim();
  if (!name) return res.status(400).json({ error: "customer_name is required" });

  const trimmedItem = item?.trim();
  if (!trimmedItem) return res.status(400).json({ error: "item is required" });

  // Step 4: Length limits
  if (name.length > 100) return res.status(400).json({ error: "customer_name too long" });
  if (trimmedItem.length > 200) return res.status(400).json({ error: "item too long" });

  // Step 5: Parse and range-check numbers
  const qty = Number(quantity);
  if (isNaN(qty) || !Number.isInteger(qty) || qty < 1 || qty > 100) {
    return res.status(400).json({ error: "quantity must be an integer between 1 and 100" });
  }

  // Step 6: Validate enums
  const VALID_STATUSES = ["received", "preparing", "ready", "delivered"];
  if (status && !VALID_STATUSES.includes(status)) {
    return res.status(400).json({ error: `status must be one of: ${VALID_STATUSES.join(", ")}` });
  }

  // Step 7: Pass validated data to service layer
  orderService.create({ name, item: trimmedItem, quantity: qty, status: status || "received" });
});
```

### Numeric ID Validation

```typescript
// RIGHT — always parse and validate IDs from URL params
app.get("/api/products/:id", (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (isNaN(id) || id <= 0) {
    return res.status(400).json({ error: "Invalid product ID" });
  }
  const product = db.prepare("SELECT * FROM products WHERE id = ?").get(id);
});
```

```csharp
// RIGHT — always parse and validate IDs from route values
[HttpGet("/api/products/{id}")]
public IActionResult GetProduct(string id)
{
    if (!int.TryParse(id, out var numericId) || numericId <= 0)
    {
        return BadRequest(new { error = "Invalid product ID" });
    }

    var product = dbConnection.QuerySingleOrDefault<Product>(
        "SELECT * FROM products WHERE id = @Id",
        new { Id = numericId });
    return Ok(product);
}
```

### Enum Validation

```typescript
// RIGHT — check against explicit allowed list
const VALID_CATEGORIES = ["electronics", "clothing", "food", "books"] as const;
type Category = (typeof VALID_CATEGORIES)[number];

function validateCategory(input: string): Category {
  if (!VALID_CATEGORIES.includes(input as Category)) {
    throw new ValidationError(`Invalid category. Must be one of: ${VALID_CATEGORIES.join(", ")}`);
  }
  return input as Category;
}
```

```csharp
private static readonly string[] ValidCategories = { "electronics", "clothing", "food", "books" };

private static string ValidateCategory(string input)
{
    if (!ValidCategories.Contains(input, StringComparer.OrdinalIgnoreCase))
    {
        throw new ValidationException($"Invalid category. Must be one of: {string.Join(", ", ValidCategories)}");
    }

    return input;
}
```

---

## Path Traversal Prevention

**Never use user input directly in file paths.** Attackers use `../` sequences to access files outside the intended directory.

```typescript
// WRONG — user controls path, can read /etc/passwd with ../../etc/passwd
app.get("/files/:name", (req, res) => {
  const filePath = path.join("/uploads", req.params.name);
  res.sendFile(filePath);
});

// RIGHT — resolve and verify the path stays within the allowed directory
app.get("/files/:name", (req, res) => {
  const uploadsDir = path.resolve("/uploads");
  const filePath = path.resolve(uploadsDir, req.params.name);

  // Verify resolved path is still within uploads directory
  if (!filePath.startsWith(uploadsDir + path.sep)) {
    return res.status(400).json({ error: "Invalid file path" });
  }

  res.sendFile(filePath);
});
```

```python
# WRONG — path traversal possible
file_path = os.path.join(UPLOAD_DIR, filename)

# RIGHT — resolve and check containment
upload_dir = os.path.realpath(UPLOAD_DIR)
file_path = os.path.realpath(os.path.join(upload_dir, filename))
if not file_path.startswith(upload_dir + os.sep):
    abort(400, "Invalid file path")
```

```csharp
// WRONG — user controls path in a file request
[HttpGet("/files/{name}")]
public IActionResult GetFile(string name)
{
    var uploadsDir = Path.GetFullPath("/uploads");
    var filePath = Path.GetFullPath(Path.Combine(uploadsDir, name));

    if (!filePath.StartsWith(uploadsDir + Path.DirectorySeparatorChar, StringComparison.Ordinal))
    {
        return BadRequest(new { error = "Invalid file path" });
    }

    return PhysicalFile(filePath, "application/octet-stream");
}
```

**Rule:** Always `path.resolve()` / `os.path.realpath()` both the base directory and the combined path, then verify the result starts with the base directory.

---

## Command Injection Prevention

**Never pass user input to shell commands.** Use language APIs or argument arrays instead.

```typescript
// WRONG — shell injection via user input
const { exec } = require("child_process");
exec(`convert ${userFilename} output.png`); // attacker: "; rm -rf /"

// WRONG — even with "sanitization", shell metacharacters are hard to fully escape
exec(`convert "${userFilename}" output.png`); // attacker: "; rm -rf / #

// RIGHT — use execFile with argument array (no shell interpretation)
const { execFile } = require("child_process");
execFile("convert", [userFilename, "output.png"], (err, stdout) => {
  // safe: arguments are not passed through a shell
});

// RIGHT — use spawn with shell: false (the default)
const { spawn } = require("child_process");
const proc = spawn("convert", [userFilename, "output.png"]);
```

```python
# WRONG — shell=True with user input
subprocess.run(f"convert {filename} output.png", shell=True)

# RIGHT — argument list, no shell
subprocess.run(["convert", filename, "output.png"], check=True)
```

```csharp
// WRONG — passing a command string to the shell
var badStartInfo = new ProcessStartInfo
{
    FileName = "cmd.exe",
    Arguments = $"/c convert {userFilename} output.png",
    UseShellExecute = false
};
Process.Start(badStartInfo);

// RIGHT — use argument list without shell interpretation
var startInfo = new ProcessStartInfo
{
    FileName = "convert",
    UseShellExecute = false,
};
startInfo.ArgumentList.Add(userFilename);
startInfo.ArgumentList.Add("output.png");

using var proc = Process.Start(startInfo);
proc.WaitForExit();
```

**Rule:** Never use `exec()`, `os.system()`, or `shell=True` with user input. Always use `execFile`/`spawn` (Node.js) or `subprocess.run` with a list (Python).

---

## SSRF Prevention

**Never let user input control outbound HTTP request URLs without validation.** Attackers use this to access internal services (e.g., `http://169.254.169.254/` for cloud metadata).

```typescript
// WRONG — user controls the URL entirely
app.post("/api/fetch-url", (req, res) => {
  const response = await fetch(req.body.url); // attacker: http://169.254.169.254/
  res.json({ data: await response.text() });
});

// RIGHT — validate URL against allowlist of domains
const ALLOWED_HOSTS = ["api.example.com", "cdn.example.com"];

app.post("/api/fetch-url", (req, res) => {
  if (!req.is("application/json")) {
    return res.status(415).json({ error: "Content-Type must be application/json" });
  }

  let parsed;
  try {
    parsed = new URL(req.body.url);
  } catch {
    return res.status(400).json({ error: "Invalid URL" });
  }

  if (!["https:"].includes(parsed.protocol)) {
    return res.status(400).json({ error: "Only HTTPS URLs allowed" });
  }
  if (!ALLOWED_HOSTS.includes(parsed.hostname)) {
    return res.status(400).json({ error: "Domain not allowed" });
  }

  const response = await fetch(parsed.toString());
  res.json({ data: await response.text() });
});
```

```csharp
// RIGHT — validate URL against allowlist of domains before issuing outbound requests
[HttpPost("/api/fetch-url")]
public async Task<IActionResult> FetchUrl([FromBody] FetchUrlDto request)
{
    if (!Request.ContentType?.Equals("application/json", StringComparison.OrdinalIgnoreCase) ?? true)
    {
        return StatusCode(StatusCodes.Status415UnsupportedMediaType, new { error = "Content-Type must be application/json" });
    }

    if (!Uri.TryCreate(request.Url, UriKind.Absolute, out var parsed))
    {
        return BadRequest(new { error = "Invalid URL" });
    }

    if (!string.Equals(parsed.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
    {
        return BadRequest(new { error = "Only HTTPS URLs allowed" });
    }

    var allowedHosts = new[] { "api.example.com", "cdn.example.com" };
    if (!allowedHosts.Contains(parsed.Host, StringComparer.OrdinalIgnoreCase))
    {
        return BadRequest(new { error = "Domain not allowed" });
    }

    var response = await httpClient.GetStringAsync(parsed);
    return Ok(new { data = response });
}
```

---

## Mass Assignment / Over-Posting Prevention

**Never pass the entire request body to a database create/update call.** Destructure only the expected fields.

```typescript
// WRONG — mass assignment: attacker adds { role: "admin" } to body
app.post("/api/users", (req, res) => {
  const user = await prisma.user.create({ data: req.body });
});

// RIGHT — explicitly pick only allowed fields
app.post("/api/users", (req, res) => {
  if (!req.is("application/json")) {
    return res.status(415).json({ error: "Content-Type must be application/json" });
  }

  const { name, email } = req.body;
  const user = await prisma.user.create({
    data: { name: name?.trim(), email: email?.trim() },
  });
});
```

```python
# WRONG — mass assignment
user = User(**request.json)

# RIGHT — pick allowed fields only
data = request.get_json()
user = User(name=data.get("name", "").strip(), email=data.get("email", "").strip())
```

```csharp
// RIGHT — explicitly map only allowed request fields
[HttpPost("/api/users")]
public IActionResult CreateUser([FromBody] UserDto dto)
{
    if (!Request.ContentType?.Equals("application/json", StringComparison.OrdinalIgnoreCase) ?? true)
    {
        return StatusCode(StatusCodes.Status415UnsupportedMediaType, new { error = "Content-Type must be application/json" });
    }

    var user = new User
    {
        Name = dto.Name?.Trim(),
        Email = dto.Email?.Trim()
    };

    dbContext.Users.Add(user);
    dbContext.SaveChanges();

    return Ok(user);
}
```

---

## Where to Validate: Layered Defense

| Layer | What to check | Example |
|---|---|---|
| **API route entry** | Content-Type, shape, types, required fields, length limits | Reject non-JSON with 415, reject missing fields with 400 |
| **Service layer** | Business rules, cross-field validation, state checks | "Quantity exceeds stock", "Order already cancelled", "User suspended" |
| **Database** | Constraints, foreign keys, unique indexes | NOT NULL, CHECK constraints, FK references |
| **Frontend** | Format hints, required fields | UX convenience only -- **never rely on this alone** |

### Service Layer Business Rules

The service layer enforces rules that depend on application state or cross-field relationships. **Always include at least one meaningful business rule check** such as existence verification, stock/capacity checks, status transition validation, or permission checks:

```typescript
// RIGHT — service layer validates business rules
class OrderService {
  async create(input: ValidatedOrderInput) {
    // Verify referenced entities exist
    const product = await this.productRepo.findById(input.productId);
    if (!product) throw new NotFoundError("Product not found");

    // Check business constraints
    if (product.stock < input.quantity) {
      throw new BusinessRuleError("Insufficient stock");
    }
    if (input.quantity > product.maxOrderQuantity) {
      throw new BusinessRuleError(`Max order quantity is ${product.maxOrderQuantity}`);
    }

    // Check user permissions / account status
    const user = await this.userRepo.findById(input.userId);
    if (user.status === "suspended") {
      throw new BusinessRuleError("Account is suspended");
    }

    // Check for duplicate orders (idempotency)
    const existing = await this.orderRepo.findByIdempotencyKey(input.idempotencyKey);
    if (existing) return existing;

    return this.orderRepo.create(input);
  }

  async updateStatus(orderId: number, newStatus: string) {
    const order = await this.orderRepo.findById(orderId);
    if (!order) throw new NotFoundError("Order not found");

    // Validate status transitions
    const VALID_TRANSITIONS = {
      received: ["preparing", "cancelled"],
      preparing: ["ready", "cancelled"],
      ready: ["completed"],
    };
    const allowed = VALID_TRANSITIONS[order.status] || [];
    if (!allowed.includes(newStatus)) {
      throw new BusinessRuleError(
        `Cannot transition from '${order.status}' to '${newStatus}'`
      );
    }

    return this.orderRepo.updateStatus(orderId, newStatus);
  }
}
```

```csharp
// RIGHT — service layer validates business rules
public class OrderService
{
    public async Task<Order> CreateAsync(ValidatedOrderInput input)
    {
        var product = await productRepo.FindByIdAsync(input.ProductId);
        if (product == null) throw new NotFoundException("Product not found");

        if (product.Stock < input.Quantity)
            throw new BusinessRuleException("Insufficient stock");

        if (input.Quantity > product.MaxOrderQuantity)
            throw new BusinessRuleException($"Max order quantity is {product.MaxOrderQuantity}");

        var user = await userRepo.FindByIdAsync(input.UserId);
        if (user.Status == "suspended")
            throw new BusinessRuleException("Account is suspended");

        var existing = await orderRepo.FindByIdempotencyKeyAsync(input.IdempotencyKey);
        if (existing != null) return existing;

        return await orderRepo.CreateAsync(input);
    }

    public async Task<Order> UpdateStatusAsync(int orderId, string newStatus)
    {
        var order = await orderRepo.FindByIdAsync(orderId);
        if (order == null) throw new NotFoundException("Order not found");

        var validTransitions = new Dictionary<string, string[]>
        {
            ["received"] = new[] { "preparing", "cancelled" },
            ["preparing"] = new[] { "ready", "cancelled" },
            ["ready"] = new[] { "completed" }
        };

        var allowed = validTransitions.ContainsKey(order.Status) ? validTransitions[order.Status] : Array.Empty<string>();
        if (!allowed.Contains(newStatus))
            throw new BusinessRuleException($"Cannot transition from '{order.Status}' to '{newStatus}'");

        return await orderRepo.UpdateStatusAsync(orderId, newStatus);
    }
}
```

**Always duplicate frontend validation on the backend.** Frontend validation improves UX but attackers bypass it with curl or modified clients.

---

## Checklist (apply to every endpoint that handles user input)

- [ ] Content-Type header checked on POST/PUT/PATCH -- reject non-JSON with 415
- [ ] All SQL queries use parameterized statements -- no string interpolation
- [ ] ORM built-in query methods used instead of raw queries (use `contains` not `$queryRaw` for LIKE)
- [ ] User-provided strings trimmed with `.trim()` and length-limited
- [ ] Numeric inputs parsed with `parseInt`/`Number` and range-checked, NaN rejected
- [ ] Enum values validated against an explicit allowed list
- [ ] No `innerHTML` or `dangerouslySetInnerHTML` / `v-html` with user data -- use textContent or DOM API
- [ ] Backend returns JSON; frontend renders with textContent or framework auto-escaping
- [ ] Server-side validation present for every field -- frontend validation never relied upon alone
- [ ] Business rules enforced in service layer (existence checks, stock/capacity, status transitions, permissions)
- [ ] File paths resolved and verified to stay within allowed directory (path traversal prevention)
- [ ] No shell execution with user input -- use execFile/spawn with argument arrays
- [ ] URLs from user input validated against domain allowlist (SSRF prevention)
- [ ] Only expected fields destructured from request body (mass assignment prevention)
- [ ] escapeHtml covers all five characters: & < > " ' (when HTML string building is unavoidable)

## Verifiers

- [input-validation](../../verifiers/input-validation.json) -- Validate and trim user input at the API boundary
- [parameterized-queries](../../verifiers/parameterized-queries.json) -- Use parameterized queries for all database operations