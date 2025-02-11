# Laravel Best Practices
<!-- TOC -->
## Table of Contents
1. [Database Interaction](#database-interaction)
2. [Middleware](#middleware)
3. [Caching](#caching)
4. [Events](#events)
5. [Logging](#logging)
6. [Commands](#commands)
7. [Notifications](#notifications)
8. [API Responses](#api-responses)
9. [Blade Templates](#blade-templates)
10. [Direct querying in Blade files](#direct-querying-in-blade-files)
11. [Using `echo` in Blade files](#using-echo-in-blade-files)
12. [Eloquent Relationships](#eloquent-relationships)
13. [Testing](#testing)
14. [Direct SQL Queries in Controllers](#direct-sql-queries-in-controllers)
15. [Database Querying](#database-querying)
16. [Validation](#validation)
17. [Security Concerns](#security-concerns)
18. [Error Handling](#error-handling)
19. [File Uploads](#file-uploads)
20. [User model](#user-model)
21. [Hardcoding configuration values](#hardcoding-configuration-values)
22. [Not using Route Model Binding](#not-using-route-model-binding)
23. [Hardcoding Dependencies instead of using Dependency Injection](#hardcoding-dependencies-instead-of-using-dependency-injection)
24. [Hardcoding configurations](#hardcoding-configurations)
25. [Mass assignment without guarded fields](#mass-assignment-without-guarded-fields)
26. [Lack of pagination for large datasets](#lack-of-pagination-for-large-datasets)
27. [Use config and language files, constants instead of text in the code](#use-config-and-language-files-constants-instead-of-text-in-the-code)
28. [Using Constants for Repeated Values](#using-constants-for-repeated-values)
29. [API Rate Limiting](#api-rate-limiting)
30. [Form Input Sanitization](#form-input-sanitization)
31. [Custom Helpers](#custom-helpers)
32. [Avoid Duplicate Queries](#avoid-duplicate-queries)
33. [Testing Practices](#testing-practices)
34. [Service Container Binding](#service-container-binding)
35. [Repository Pattern](#repository-pattern)
36. [Using Static Methods](#using-static-methods)
37. [Queue Jobs](#queue-jobs)
38. [Centralised Business Logic](#centralised-business-logic)
39. [Use Proper Exception Handling](#use-proper-exception-handling)
40. [Best Practices accepted by community](#best-practices-accepted-by-community)
41. [Laravel Naming Conventions](#laravel-naming-conventions)
42. [Interview Questions](#interview-questions)
    1. [Beginner](#beginner)
    2. [Intermediate](#intermediate)
    3. [Expert](#expert)
    4. [General](#general)
    5. [Authentication and Authorization Questions](#authentication-and-authorization-questions)
    6. [Miscellaneous Questions](#miscellaneous-questions)
<!-- /TOC -->

## Database Interaction
### **Bad**
```php
class ProductController extends Controller
{
    public function show()
    {
        $products = DB::table('products')->where('active', 1)->get();
        return view('products.index', ['products' => $products]);
    }
}
```
### **Good**
```php
use App\Models\Product;

class ProductController extends Controller
{
    public function index()
    {
        $products = Product::active()->get();
        return view('products.index', compact('products'));
    }
}
```
The **Good** approach follows best practices by: 
- Using Eloquent ORM instead of raw queries, making the code more readable, maintainable, and reusable.
- It utilizes a query scope (`active()`) for filtering, improving reusability, and `compact()` for cleaner variable passing to the view.

### **Bad**
```php
class UserController extends Controller
{
    public function index()
    {
        // Query the database directly in the controller
        $users = DB::table('users')->get();

        return view('users.index', compact('users'));
    }

    public function store(Request $request)
    {
        // No validation, direct database insertion
        DB::table('users')->insert([
            'name' => $request->input('name'),
            'email' => $request->input('email'),
            'password' => bcrypt($request->input('password')),
        ]);

        return redirect()->route('users.index');
    }
}
```
### **Good**
```php
class UserController extends Controller
{
    public function index()
    {
        // Use Eloquent model to fetch users
        $users = User::all();

        return view('users.index', compact('users'));
    }

    public function store(UserRequest $request)
    {
        // Validation logic is handled through a custom Form Request class
        User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
        ]);

        return redirect()->route('users.index');
    }
}
```
The **Good** approach improves readability, maintainability, and security by: 
- Using Eloquent instead of raw queries.
- It leverages a Form Request (`UserRequest`) for validation, keeping the controller clean and ensuring data integrity.
- Using `User::create()` follows Laravel's mass assignment best practices, making the code more concise and easier to manage.

---
## Middleware
### **Bad**
```php
public function handle($request, Closure $next)
{
    if (Auth::user()->role !== 'admin') {
        return response('Unauthorized.', 403);
    }

    return $next($request);
}
```
### **Good**
```php
public function handle($request, Closure $next)
{
    if (!Auth::user() || !Auth::user()->hasRole('admin')) {
        abort(403, 'Unauthorized action.');
    }

    return $next($request);
}
```
The **Good** approach improves security and readability by: 
- Properly checking if the user is authenticated before accessing their role.
- It uses `abort(403)` for cleaner error handling and leverages a role-checking method (`hasRole()`), making the code more reusable and maintainable.

---
## Caching
### **Bad**
```php
$products = DB::table('products')->get();
Cache::put('products', $products, 3600);
```
### **Good**
```php
$products = Cache::remember('products', 3600, function () {
    return Product::all();
});
```
The **Good** approach improves performance and efficiency by: 
- Using `Cache::remember()`, which avoids unnecessary database queries.
- It only queries the database if the cache is empty, making the code more optimized, readable, and maintainable.

---
## Events
### **Bad**
```php
public function store(Request $request)
{
    $user = User::create($request->validated());
    Mail::to($user->email)->send(new WelcomeMail($user));
}
```
### **Good**
```php
public function store(Request $request)
{
    $user = User::create($request->validated());
    event(new UserRegistered($user));
}
```
Event Listener:
```php
public function handle(UserRegistered $event)
{
    Mail::to($event->user->email)->send(new WelcomeMail($event->user));
}
```
The **Good** approach follows the event-driven design pattern, improving scalability and maintainability yy:
- Dispatching a `UserRegistered` event, it decouples the email-sending logic from the controller, making it easier to manage and extend (e.g., logging, notifications).
- This keeps the controller clean and adheres to Single Responsibility Principle (SRP).

---
## Logging
### **Bad**
```php
Log::info('Something went wrong: ' . $e->getMessage());
```
### **Good**
```php
Log::error('Exception encountered.', ['error' => $e->getMessage(), 'trace' => $e->getTraceAsString()]);
```
The **Good** approach improves error logging and debugging by: 
- Using `Log::error()` instead of `Log::info()`, ensuring proper log severity.
- It also logs structured data (`error` message and `trace`), making it easier to analyse issues and track errors efficiently.

---
## Commands
### **Bad**
```php
public function handle()
{
    DB::table('orders')->where('status', 'pending')->delete();
}
```
### **Good**
```php
public function handle()
{
    Order::pending()->delete();
}
```
The **Good** approach improves readability, maintainability, and reusability by:
- Using Eloquent instead of raw queries. It leverages a query scope (`pending()`) for filtering, making the code cleaner and reusable across the application.

---
## Notifications
### **Bad**
```php
Mail::to($user->email)->send(new ResetPasswordMail($token));
```
### **Good**
```php
$user->notify(new ResetPasswordNotification($token));
```
The **Good** approach improves flexibility and maintainability by:
- Using Laravel's notification system instead of directly sending an email.
- This allows sending password reset notifications via multiple channels (e.g., email, SMS) without modifying the core logic, making the code more scalable and reusable.

---
## API Responses
### **Bad**
```php
return response()->json(['data' => $data], 200);
```
### **Good**
```php
return response()->json([
    'status' => 'success',
    'data' => $data,
], 200);
```
The **Good** approach improves consistency and clarity in API responses by:
- Explicitly including a `status` field, making it easier for clients to handle responses.
- This follows best practices for structured API responses, improving readability and maintainability.

---
## Blade Templates
### **Bad**
```php
@if ($user->role == 'admin')
    <p>Welcome Admin</p>
@endif
```
### **Good**
```php
@can('viewAdminDashboard', $user)
    <p>Welcome Admin</p>
@endcan
```
The **Good** approach improves security and maintainability by:
Using Laravel's authorization policies (`@can`). Instead of directly checking the role, it leverages permission logic, making it more scalable, reusable, and secure by centralizing access control.

---
## Direct querying in Blade files
### **Bad**
```
<h1>Users</h1>
@foreach (User::all() as $user)
    <p>{{ $user->name }}</p>
@endforeach
```
### **Good** 
Controller
```php
public function index()
{
    $users = User::all();
    return view('users.index', compact('users'));
}
```
**Blade**
```php
<h1>Users</h1>
@foreach ($users as $user)
    <p>{{ $user->name }}</p>
@endforeach
```
The **Good** approach improves performance, readability, and maintainability by:
- Following the MVC pattern. Fetching data in the controller prevents query execution inside the Blade view, reducing N+1 query issues and keeping the view clean and focused on presentation.

---
## Using `echo` in Blade files
### **Bad**
```php
<p><?php echo $user->name; ?></p>
```
### **Good**
```php
<p>{{ $user->name }}</p>
```
### **Even better**
```php
<p>{{ $user->name ?? 'Guest' }}</p>
```
The **Good** approach improves readability and security by:
- Using Blade's `{{ }}` syntax, which automatically escapes output, preventing XSS attacks.

The **Even Better** approach adds a null coalescing fallback (`?? 'Guest'`)
- Ensuring a default value is displayed if `$user->name` is `null`, improving user experience and preventing errors.

---
## Eloquent Relationships
### **Bad**
```php
$comments = DB::table('comments')->where('post_id', $postId)->get();
```
### **Good**
```php
$comments = $post->comments;
```
The **Good** approach improves readability, maintainability, and performance by:
- Leveraging Eloquent relationships instead of raw queries.
- Using `$post->comments` utilizes the defined relationship in the model, making the code cleaner, reusable, and more efficient by reducing direct database queries.

---
## Testing
### **Bad**
```php
public function testExample()
{
    $this->get('/home')->assertStatus(200);
}
```
### **Good**
```php
public function testHomePageLoadsCorrectly()
{
    $this->get('/home')
        ->assertStatus(200)
        ->assertSee('Welcome')
        ->assertDontSee('Error');
}
```
The **Good** approach improves clarity, coverage, and maintainability in testing by:
- Using a descriptive test method name (`testHomePageLoadsCorrectly`) for better readability.
- Adding assertions (`assertSee`, `assertDontSee`) to check for specific content, ensuring the page loads correctly.
- Making tests more robust and meaningful, catching potential issues beyond just the status code.

---
## Direct SQL Queries in Controllers
### **Bad** 
```php
public function index()
{
    $users = DB::select('SELECT * FROM users');
    return response()->json($users);
}
```
### **Good**
```php
use App\Models\User;

public function index()
{
    $users = User::all();
    return response()->json($users);
}
```
The **Good** approach improves readability, maintainability, and security by using Eloquent (`User::all()`) instead of raw SQL queries. This ensures:
- Cleaner and more expressive code
- Built-in protection against SQL injection
- Easier integration with Eloquent features (e.g., scopes, relationships)
- Database abstraction, making it easier to switch databases if needed

---
## Database Querying
### **Bad**
```php
// Direct query execution without optimization
$users = DB::table('users')
    ->join('orders', 'users.id', '=', 'orders.user_id')
    ->where('orders.created_at', '>', now()->subMonth())
    ->select('users.name', 'orders.total')
    ->get();
```
### **Good**
```php
class UserController extends Controller
{
    public function index()
    {
        // Use Eloquent relationships and eager loading
        $users = User::with('orders')->whereHas('orders', function($query) {
            $query->where('created_at', '>', now()->subMonth());
        })->get();

        return view('users.index', compact('users'));
    }
}
```
The **Good** approach improves performance, readability, and maintainability by:
- Using Eloquent relationships (`with('orders')`) instead of raw joins, making the query more expressive and easier to manage.
- Leveraging `whereHas()` to filter users efficiently based on their orders, reducing unnecessary data retrieval.
- Eager loading (`with()`) to prevent N+1 query issues, optimizing database performance.
- Keeping the controller clean and following Laravel best practices.

---
## Validation
### **Bad**
```php
public function store(Request $request)
{
    // No validation, using raw request data
    $user = new User;
    $user->name = $request->input('name');
    $user->email = $request->input('email');
    $user->password = bcrypt($request->input('password'));
    $user->save();
}
```
### **Good**
```php
class UserRequest extends FormRequest
{
    public function rules()
    {
        return [
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|min:8|confirmed',
        ];
    }
}
```
**Controller**
```php
public function store(UserRequest $request)
{
    $user = User::create($request->validated());
}
```
The **Good** approach improves security, readability, and maintainability by:
- Using a Form Request (`UserRequest`) to handle validation, keeping the controller clean and enforcing data integrity.
- Utilizing mass assignment (`User::create()`), making the code more concise and readable while adhering to Laravel's best practices.
- Ensuring better security by preventing unvalidated data from being stored, reducing the risk of injection attacks or invalid data.

---
## Security Concerns
### **Bad** 
```php
public function login(Request $request)
{
    $user = User::where('email', $request->email)->first();

    if ($user && Hash::check($request->password, $user->password)) {
        Auth::login($user);
        return redirect()->route('dashboard');
    }

    return back()->withErrors(['email' => 'Invalid credentials']);
}
```
### **Good**
```php
public function login(Request $request)
{
    $credentials = $request->only('email', 'password');

    if (Auth::attempt($credentials)) {
        return redirect()->route('dashboard');
    }

    return back()->withErrors(['email' => 'Invalid credentials']);
}
```
The **Good** approach improves security, readability, and maintainability by:
- Using `Auth::attempt($credentials)`, which automatically handles user retrieval and password verification, reducing manual checks.
- Ensuring cleaner and more concise code, making it easier to read and maintain.
- Relying on Laravel’s authentication system, which includes built-in security measures like throttling and hashing, reducing the risk of security vulnerabilities.

---
## Error Handling
### **Bad**
```php
public function show($id)
{
    $user = User::find($id);

    if (!$user) {
        return response('User not found', 404);
    }

    return view('users.show', compact('user'));
}
```
### **Good**
```php
public function show($id)
{
    $user = User::findOrFail($id);

    return view('users.show', compact('user'));
}
```
The **Good** approach improves readability, efficiency, and error handling by:
- Using `findOrFail($id)`, which automatically returns a 404 error response if the user is not found, eliminating the need for manual checks.
- Keeping the code clean and concise, making it easier to read and maintain.
- Leveraging Laravel’s built-in exception handling, which ensures a standardized error response across the application.

---
## File Uploads
### **Bad**
```php
public function upload(Request $request)
{
    $request->file('image')->move('uploads', 'image.jpg');
}
```
### **Good**
```php
public function upload(Request $request)
{
    $request->validate([
        'image' => 'required|image|mimes:jpeg,png,jpg,gif|max:2048',
    ]);

    $path = $request->file('image')->store('uploads', 'public');

    return response()->json(['path' => $path]);
}
```
The **Good** approach improves security, validation, and maintainability by:
- Validating the uploaded file to ensure it is an image with allowed formats and size limits, preventing security risks.
- Using `store()` instead of `move()`, which leverages Laravel's filesystem abstraction, ensuring better security and flexibility.
- Storing files in the configured storage disk (`public`), making it easier to manage and retrieve uploaded files.
- Returning a JSON response with the file path, making it suitable for APIs and frontend

---
## User model 
### **Full name**
### **Bad**
```php
public function getFullNameLong(): string
{
    return 'Mr. ' . $this->first_name . ' ' . $this->middle_name . ' ' . $this->last_name;
}
```
### **Good**
```php
public function getFullNameLong(): string
{
    return $this->title . ' ' . $this->first_name . ' ' . $this->middle_name . ' ' . $this->last_name;
}
```
### **Better**
```php
public function getFullNameLong(): string
{
    return $this->title . ' ' . ($this->first_name ?? '') . ' ' . ($this->middle_name ?? '') . ' ' . ($this->last_name ?? '');
}
```
The **Good** approach improves flexibility and maintainability by:
- Dynamically using the `title` property instead of hardcoding `'Mr.'`, making it adaptable for different titles.

The **Better** approach further enhances robustness by:
- Using the null coalescing operator (`?? ''`), preventing potential `null` values from causing unwanted gaps or errors in the output.
- This ensures a consistent and clean full name format regardless of missing values.

### **Short name**
### **Bad**
```php
public function getFullNameShort(): string
{
    return $this->first_name[0] . '. ' . $this->last_name;
}
```
### **Good**
```php
public function getFullNameShort(): string
{
    $firstNameInitial = !empty($this->first_name) ? $this->first_name[0] . '.' : '';
    return $firstNameInitial . ' ' . $this->last_name;
}
```
The **Good** approach improves robustness and prevents errors by:
- Handling cases where `first_name` might be empty or null, avoiding potential undefined index errors.
- Using a conditional check (`!empty($this->first_name)`) to ensure the first name exists before accessing its first character.
- Providing a cleaner and safer way to format the short name, preventing unexpected issues in edge cases.

---
## Hardcoding configuration values
### **Bad** 
```php
public function sendEmail()
{
    $to = 'example@example.com';
    $subject = 'Hello World';
    mail($to, $subject, 'This is a test email.');
}
```
### **Good**
```php
use Illuminate\Support\Facades\Mail;

public function sendEmail()
{
    Mail::to(config('mail.default_to_address'))->send(new App\Mail\WelcomeMail());
}
```
The **Good** approach improves security, maintainability, and flexibility by:
- Using Laravel’s `Mail` facade, which integrates with various mail drivers (SMTP, Mailgun, Postmark, etc.), making email handling more reliable and configurable.
- Avoiding hardcoded email addresses by using `config('mail.default_to_address')`, ensuring environment-based configuration.
- Sending a properly structured Mailable (`WelcomeMail`), making emails reusable, testable, and maintainable.

---
## Not using Route Model Binding
### **Bad**
```php
public function show($id)
{
    $user = User::find($id);
    if (!$user) {
        abort(404);
    }
    return view('user.show', compact('user'));
}
```
### **Good**
```php
public function show(User $user)
{
    return view('user.show', compact('user'));
}
```

The **Good** approach improves readability, efficiency, and error handling by:
- Using route model binding (`User $user`), which automatically retrieves the user by ID, eliminating the need for a manual query.
- Automatically returning a 404 response if the user is not found, simplifying error handling.
- Keeping the controller method cleaner and more concise, improving maintainability.

---
## Hardcoding Dependencies instead of using Dependency Injection
### **Bad**
```php
public function sendNotification()
{
    $mailer = new \App\Services\Mailer();
    $mailer->send('Hello World');
}
```
### **Good**
```php
use App\Services\Mailer;

public function sendNotification(Mailer $mailer)
{
    $mailer->send('Hello World');
}
```
The **Good** approach improves maintainability, testability, and dependency management by:
- Using dependency injection (`Mailer $mailer`) instead of manually instantiating the class, making the code more flexible and easier to test.
- Allowing Laravel's service container to handle dependencies, making it easier to swap implementations (e.g., using a mock for testing).
- Promoting cleaner and more reusable code by following the Dependency Injection (DI) principle.

---
## Hardcoding configurations
### **Bad**
```php
$apiKey = '12345'; // API key hardcoded
```
### **Good**
```php
$apiKey = config('services.api.key');
```
The **Good** approach improves security, maintainability, and flexibility by:
- Storing the API key in Laravel's configuration files (`config/services.php`), preventing hardcoded sensitive information.
- Allowing easy environment-based configuration by fetching the key from `.env`, making it adaptable for different environments (local, staging, production).
- Enhancing security by keeping sensitive data out of the codebase, reducing the risk of exposure in version control.

---
## Mass assignment without guarded fields
### **Bad**
```php
public function store(Request $request)
{
    User::create($request->all());
}
```
### **Good**
Inside `User` model
```php
protected $fillable = ['name', 'email', 'password'];
```
Inside the controller
```php
public function store(Request $request)
{
    $data = $request->only(['name', 'email', 'password']);
    $data['password'] = bcrypt(data['password']);

    User::create($data);
}
```
The **Good** approach improves security, data integrity, and maintainability by:
- Using `$fillable` in the model to prevent mass assignment vulnerabilities, ensuring only allowed fields are mass-assigned.
- Explicitly selecting input fields (`only(['name', 'email', 'password'])`), preventing unwanted or malicious data from being stored.
- Hashing passwords (`bcrypt($data['password'])`) before storing them, ensuring proper security practices.
- Making the code cleaner and more maintainable, following Laravel's best practices.

---
## Lack of pagination for large datasets
### **Bad**
```php
public function index()
{
    $users = User::all();
    return response()->json($users);
}
```
### **Good**
```php
public function index()
{
    $users = User::paginate(10);
    return response()->json($users);
}
```
The **Good** approach improves performance, scalability, and user experience by:
- Using pagination (`paginate(10)`) instead of retrieving all records at once, preventing potential performance issues with large datasets.
- Returning a structured response that includes pagination metadata (e.g., total pages, current page), making it easier for frontend applications to handle.
- Following best practices for API responses, ensuring efficient data retrieval without overwhelming the database or API consumers.

---
## Use config and language files, constants instead of text in the code
### **Bad**
```php
public function isNormal(): bool
{
    return $article->type === 'normal';
}

return back()->with('message', 'Your article has been added!');
```
### **Good**
```php
public function isNormal()
{
    return $article->type === Article::TYPE_NORMAL;
}

return back()->with('message', __('app.article_added'));
```

The **Good** approach improves maintainability, readability, and localization by:
- Using a constant (`Article::TYPE_NORMAL`) instead of a hardcoded string (`'normal'`), reducing errors and making the code more maintainable.
- Utilizing Laravel’s localization helper (`__('app.article_added')`), allowing the message to be easily translated into multiple languages.
- Following clean coding principles, making the code more structured and adaptable to future changes.

---
## Using Constants for Repeated Values
### **Bad**
```php
if ($user->type === 'admin') {
    // Perform action
}
```
### **Good**
```php
class User
{
    public const TYPE_ADMIN = 'admin';
    public const TYPE_CUSTOMER = 'customer';
}
```
Usage
```php
if ($user->type === User::TYPE_ADMIN) {
    // Perform action
}
```
The **Good** approach improves maintainability, readability, and reduces errors by:
- Defining constants (`User::TYPE_ADMIN`) instead of using hardcoded strings, making the code easier to update and less error-prone.
- Enhancing code clarity by centralizing user type definitions in the `User` model.
- Preventing typos and inconsistencies when checking user types throughout the application.
- Making it easier to refactor if the user type values need to change in the future.

---
## API Rate Limiting
### **Bad**
```php
Route::get('/api/resource', [ApiController::class, 'index']);
```
### **Good**
```php
Route::middleware('throttle:60,1')->get('/api/resource', [ApiController::class, 'index']);
```
The **Good** approach improves security, performance, and API reliability by:

- Adding rate limiting (`throttle:60,1`), which restricts the number of requests (60 per minute) to prevent abuse and protect server resources.
- Enhancing API security by reducing the risk of DDoS attacks or excessive requests from malicious users.
- Following best practices for API development, ensuring fair usage and better user experience.

---
## Form Input Sanitization
### **Bad**
```php
$input = $request->all();
```
### **Good**
```php
$input = $request->only(['name', 'email', 'password']);
```
The **Good** approach improves security, data integrity, and maintainability by:
- Using `only(['name', 'email', 'password'])` to explicitly specify which fields to retrieve, preventing mass assignment vulnerabilities.
- Avoiding unintended or malicious input from being processed if extra fields are sent in the request.
- Making the code more predictable and secure, following Laravel best practices for handling user input.

---
## Custom Helpers
### **Bad**
```php
function calculateAge($birthdate)
{
    return \Carbon\Carbon::parse($birthdate)->age;
}
```
### **Good**
Create a dedicated helper file:
```php
if (!function_exists('calculateAge')) {
    function calculateAge($birthdate)
    {
        return \Carbon\Carbon::parse($birthdate)->age;
    }
}
```
Register the helper in `composer.json`:
```php
"autoload": {
    "files": [
        "app/helpers.php"
    ]
}
```
The **Good** approach improves reusability, maintainability, and performance by:
- Defining the function in a helper file, making it globally accessible without needing to repeat the logic in multiple places.
- Using `function_exists()` to prevent redeclaration errors and avoid conflicts.
- Autoloading the helper via `composer.json`, ensuring it is available throughout the application without manual imports.
- Following best practices for reusable utility functions, making the codebase cleaner and more maintainable.

---
## Avoid Duplicate Queries
### **Bad**
```php
foreach ($users as $user) {
    $profile = $user->profile; // Triggers N+1 query issue
}
```
### **Good**
```php
$users = User::with('profile')->get();
foreach ($users as $user) {
    $profile = $user->profile;
}
```
The **Good** approach improves performance and database efficiency by:
- Using Eager Loading (`with('profile')`) to retrieve related profiles in a single query, preventing the N+1 query problem.
- Reducing database load by fetching all necessary data at once, improving response time and scalability.
- Following Laravel best practices for optimizing queries, ensuring a more efficient and maintainable codebase.

---
## Testing Practices
### **Bad**
```php
public function testUserCanLogin()
{
    $response = $this->post('/login', ['email' => 'user@example.com', 'password' => 'password']);
    $response->assertStatus(200);
}
```
### **Good**
```php
public function testUserCanLogin()
{
    $response = $this->post('/login', ['email' => 'user@example.com', 'password' => 'password']);
    $response->assertStatus(200)
        ->assertJsonStructure(['token']);
}
```
The **Good** approach improves test accuracy, API validation, and reliability by:
- Checking the response structure with `assertJsonStructure(['token'])`, ensuring the login API returns a token (or expected data).
- Enhancing test coverage by verifying both the HTTP status and the response format, making the test more meaningful.
- Following best practices for API authentication testing, ensuring the expected output is correctly implemented.

---
## Service Container Binding
### **Bad**
```php
$userRepo = new EloquentUserRepository();
```
### **Good**
Bind the repository in a service provider
```php
$this->app->bind(UserRepository::class, EloquentUserRepository::class);
```
Usage:
```php
$userRepo = app(UserRepository::class);
```

The **Good** approach improves maintainability, testability, and flexibility by:
- Using Dependency Injection via Laravel’s Service Container, making the code loosely coupled and easier to swap implementations.
- Following the Repository Pattern, which separates data access logic from business logic, enhancing code organization.
- Simplifying unit testing by allowing mocking of `UserRepository`, making tests more isolated and reliable.
- Promoting scalability, as different repository implementations (e.g., `CacheUserRepository`) can be easily introduced without modifying dependent code.

---
## Repository Pattern
### **Bad**
```php
class UserController extends Controller
{
    public function index()
    {
        $users = User::all();
        return view('users.index', compact('users'));
    }
}
```
### **Good**
```php
interface UserRepository
{
    public function getAll();
}
```
Repository Implementation:
```php
class EloquentUserRepository implements UserRepository
{
    public function getAll()
    {
        return User::all();
    }
}
```
Controller Usage:
```php
class UserController extends Controller
{
    private UserRepository $userRepository;

    public function __construct(UserRepository $userRepository)
    {
        $this->userRepository = $userRepository;
    }

    public function index()
    {
        $users = $this->userRepository->getAll();
        return view('users.index', compact('users'));
    }
}
```
The **Good** approach improves code maintainability, flexibility, and testability by:
- Applying the Repository Pattern, which separates database logic from controllers, making code more modular.
- Using Dependency Injection, allowing different implementations (e.g., `CacheUserRepository`) without modifying controller logic.
- Enhancing testability, as the repository can be easily mocked for unit tests.
- Following SOLID principles, particularly Dependency Inversion (D in SOLID), by depending on an interface rather than a concrete class.

---
## Using Static Methods
### **Bad**
```php
class UserHelper
{
    public static function isAdmin($user)
    {
        return $user->role === 'admin';
    }
}
```
### **Good**
```php
class UserHelper
{
    public function isAdmin($user)
    {
        return $user->role === 'admin';
    }
}
```
Usage:
```php
$userHelper = new UserHelper();
$userHelper->isAdmin($user);
```
The **Good** approach improves testability, flexibility, and adherence to best practices by:
- Avoiding static methods, which make unit testing harder since they cannot be mocked.
- Allowing Dependency Injection, enabling the helper to be injected where needed instead of relying on direct static calls.
- Following Object-Oriented Principles, making the helper extensible and reusable in different contexts.
- Improving maintainability, as instance-based classes can be easily replaced or extended without modifying all static calls.

---
## Queue Jobs
### **Bad**
```php
public function sendNotification(Request $request)
{
    Mail::to($request->email)->send(new NotificationMail());
}
```
### **Good**
```php
NotificationJob::dispatch($request->email);
```
Job Implementation:
```php
class NotificationJob implements ShouldQueue
{
    public function __construct(public string $email) {}

    public function handle()
    {
        Mail::to($this->email)->send(new NotificationMail());
    }
}
```
The **Good** approach improves performance and scalability by:
- Using a Queue: Offloading email sending to a background job prevents request delays.
- Enhancing User Experience: The user does not have to wait for the email to be sent before getting a response.
- Better Error Handling & Retries: Jobs can be retried automatically if they fail.
- Improving Maintainability: Separating concerns makes the code more modular and testable.

---
## Centralised Business Logic
### **Bad**
```php
public function calculateDiscount($price, $discountPercentage)
{
    return $price - ($price * ($discountPercentage / 100));
}
```
### **Good**
```php
class DiscountService
{
    public function calculate($price, $discountPercentage)
    {
        return $price - ($price * ($discountPercentage / 100));
    }
}
```
The **Good** approach improves separation of concerns, testability, and maintainability by:
- Encapsulating the logic in a service class: This makes the discount calculation reusable across the application, making it easier to manage changes.
- Following Single Responsibility Principle (SRP): The `DiscountService` has a single responsibility—handling the discount calculation.
- Enhancing testability: The service can be mocked or tested independently, making unit tests cleaner and more focused.
- Improving maintainability: The calculation logic is centralized in one place, so future updates or changes to the discount logic are easier to implement without modifying multiple parts of the codebase.

---
## Use Proper Exception Handling
### **Bad**
```php
public function show($id)
{
    $user = User::find($id);
    
    if (!$user) {
        return response()->json(['error' => 'User not found'], 404);
    }
    
    return response()->json($user);
}

```
### **Good**
```php
public function show($id)
{
    $user = User::findOrFail($id);
    return response()->json($user);
}

```
The **Good** approach improves readability, simplicity, and error handling by:
- Using `findOrFail`: This method automatically throws a `ModelNotFoundException` if the user is not found, simplifying the code and removing the need for manual error handling.
- Reducing boilerplate: No need to manually check if the user exists and return a custom error message; `findOrFail` handles this efficiently.
- Automatic Exception Handling: The `findOrFail` method triggers Laravel's built-in exception handler, which will return a proper 404 response.
- Improving consistency: The use of `findOrFail` aligns with Laravel's conventions, ensuring the code is consistent with the framework's error handling approach.

---
## Best Practices accepted by community
Laravel has some built in functionality and community packages can help instead of using 3rd party packages and tools.
| Task | Standard Tools | 3rd Party Tools | 
|---|---|---|
| Authorization | Policies | Entrust, Sentinel and other packages |
| Compiling Assests | Laravel Mix, Vite | Grunt, Gulp, and other packages |
| Development Environment | Laravel Sail, Homestead | Docker |
| Deployment | Laravel Forge | Deployer and other solutions | 
| Unit Testing | PHPUnit | Pest |
| Browser Testing | Laravel Dusk | Codeception | 
| DB | Eloquent | SQL, Doctrine |
| Templates | Blade | Twig |
| Working With Data | Laravel Collections | Arrays |
| Form Validation | Request classes | Validation in controller | 
| Authentication | Built In | 3rd party packages, your own solution | 
| API authentication | Laravel Passport, Laravel Sanctum | 3rd party JWT and OAuth packages | 
| Creating an API | Built in | Dingo API or similar |
| Working with DB structure | Migrations | Working directly with the DB |
| Localisition | Built in | 3rd party packages |
| Realtime user interfaces | Laravel Echo, Pusher | 3rd party packages and working with WebSockets directly |
| Generating testing data | Seeder classes, Model Factories, Faker | Creating testing data manually |
| Task scheduling | Laravel Task Scheduler | Scripts and 3rd party packages |
| DB | MySQL, PostgreSQL, SQLite, SQL Server | MongoDB|
| Queues & Job Handling | Laravel Queues, Horizon | RabbitMQ, Beanstalkd |
| Rate Limiting | Laravel Throttle Middleware | Custom-built solutions | 
| Logging | Monolog (built-in) | Custom logging solutions |
| Error Handling | Laravel Exception Handler | Sentry, Bugsnag |
| Email | Laravel Mail (Mailables) | PHPMailer, SwiftMailer |
| Notifications | Laravel Notifications | Custom-built solutions |
| File Storage | Laravel Filesystem (Flysystem) | Direct file system manipulation |
| Background Jobs | Laravel Queues | Custom cron jobs |
| Caching | Laravel Cache (Redis, Memcached, File) | Custom caching solutions |
| Search | Laravel Scout | Elasticsearch, Algolia |
| Multi-Tenancy | Laravel Tenancy | Custom implementations | 
| Monitoring & Debugging | Laravel Telescope | Custom logging dashboards |
| Security | Laravel Security Middleware | Custom security implementations |
| Multi-Language Support | Laravel Localization | Poedit, custom solutions |
| API Documentation | Laravel OpenAPI, L5-Swagger | Postman collections |
| Social Authentication | Laravel Socialite	| Custom OAuth integrations |
| PDF Generation | DomPDF, Snappy | TCPDF, custom solutions |

---
## Laravel Naming Conventions 
To follow PSR standards
And, follow naming conventions accepted by the Laravel community: 
| What | How | Good | Bad |
|---|---|---|---|
| Controller | Singular | `ArticaleController` | `ArticalesController` |
| Route | Plural | `articles/1` | `article/1` |
| Route Name | snake_case with dot notation | `users.show_active` | `users.show-active`, `show-active-users` |
| Model | Singular | `User` | `Users` |
| hasOne or belongsTo relationship | Singular | `articleComment` | `articleComments`, `article_comments` |
| All other relationships | Plural | `articleComments` | `articleComment`, `article_comments` | 
| Table | Plural | `article_comments` | `article_comment`, `articleComments` |
| Pivot Table | Singular model names in alphabetical order | `article_user` | `users_article`, `articles_users` |
| Table Column | snake_case without model name | `meta_title` | `MetaTitle`, `article_meta_title` |
| Model Proprty | snake_case | `$model->created_at` | `$model->createdAt` |
| Foreign Key | Singular model name with _id suffix | `article_id` | `ArticleId`, `id_article`, `article_id` |
| Primary Key | - | `id` | `custom_id` | 
| Migration | - | `2017_01_01_000000_create_articles_table` | `2017_01_01_000000_articles` | 
| Method | camelCase | `getAll` | `get_all` |
| Method in resource controller | Table | `store` | `saveArticle` |
| Method in test class | camelCase | `testGuestCannotSeeArticle` | `test_guest_cannot_see_article` | 
| Variable | camelCase | `$articlesWithAuthor` | `$articles_with_author` |
| Collection | Descriptive, Plural | `$activeUsers = User::active()->get()` | `$active`, `$data` |
| Object | Descriptive, Singular | `$activeUser = User::active()->first()` | `$users`, `$obj` | 
| Config and language files index | snake_case | `articles_enabled` | `ArticlesEnabled`, `articles-enabled` |
| View | kabab-case | `show-filtered.blade.php` | `showFiltered.blade.php`, `show_filtered.blade.php` |
| Config | snake_case | `google_calendar.php` | `googleCalendar.php`, `google-calendar.php` |
| Contract (Interface) | Adjective or noun | `AuthenticationInterface` | `Authenticatable`, `IAuthentication` | 
| Trait | Adjective | `Notifiable` | `NotificationTrait` |
| Trait (PSR) | Adjective | `NotifiableTrait` | `Notification` |
| Enum | Singular | `UserType` | `UserTypes`, `UserTypeEnum` |
| Form Request | Singular | `UpdateUserRequest` | `UpdateUserFormRequest`, `UserFormRequest`, `UserRequest` | 
| Seeder | Singular | `UserSeeder` | `UsersSeeder` |
| Language File Names | Lower case, snake_case | `user_management.php`, `order_status.php` | `UserManagement.php`, `OrderStatus.php` |
| Language Files | Lower case, snake_case | `'login_failed'`, `'user'` | `'LoginFailed'`, `'User'` |
| Event | Verb in past tense | `userRegistered` | `RegisterUserEvent` |
| Listener | Verb in present tense | `SendUserWelcomeEmail` | `UserWelcomeEmailSender` | 
| Job | Verb in present tense | `ProcessPayment` | `PaymentProcessingJob` | 
| Command | Verb in present tense | `ClearCache` | `CacheClearCommand` | 
| Policy | Singular, matching model | `ArticlePolicy` | `ArticlesPolicy` | 
| Helper Function | snake_case | `format_date()` | `formatDate() ` |
| Enum Cases | UPPER_CASE | `UserType::ADMIN` | `UserType::Admin`, `UserType::admin` |

---
## Interview Questions
### Beginner
- What is Laravel?
  - Laravel is a PHP framework based on the MVC (Model-View-Controller) architecture, designed to make web development easier and faster by providing built-in features like routing, authentication, session management, and more.
- What is Composer in Laravel?
  - Composer is a dependancy manager for PHP. It helps manage the libraries and packages required for a Laravel project.
- What are the benefits of using Laravel?
  - Built-in tools for common tasks like routing, sessiong handling, and authentication.
  - Elegant syntax and expressive ORM (Eloquent).
  - Scalability and maintainability.
  - Robust security features.
- What are service providers in Laravel?
  - Service providers are the central place to configure and bootstrap your application. Laravel's core services are all bootstrapped through service providers.
- What is the Artisan CLI tool?
  - Artisan is Laravel's command-line interface that provides various commands to assist developers, such as creating controllers, migrations, and more
### Intermediate
- Explain Eloquent ORM in Laravel.
  - Eloquent is Laravel's built-in ORM, providing an easy-to-use Active Record implementation. It allows developers to interact with the database by defining models and relationships instead of writing raw SQL queries.
- What are middleware in Laravel?
  - Middleware is a way to filter HTTP requests entering your application. Examples include authentication and logging.
- What are migrations in Laravel?
  - Migrations are version control for your database. They allow you to modify the database schema programmatically and share the schema across teams.
- How does routing work in Laravel?
  - Routes in Laravel are defined in `routes/web.php` for web routes and `routes/api.php` for API routes. A typical route is defined using:
    ```php
    Route::get('/path', [Controller::class, 'method']);
    ```
- How do you handle validation in Laravel?
  - Validation can be handled using the `validate` method in a controller or by creating a Form Request class.
- What are queues in Laravel?
  - Queues allow you to defer the processing of time-consuming tasks, such as sending emails, or processing large files.
- What is the differences between `require` and `use` in Laravel?
  - `require` includes files in PHP, whereas `use` is used to include namespaces or traits.
### Expert
- Explain service container in Laravel.
  - The service container is a powerful tool for managing class dependencies and performing dependency injection.
- What is a Repository pattern in Laravel?
  - The Repository pattern separates the logic that retrieves data from the database from the business logic. It improves code readability and testability.
- What is Laravel Event Broadcasting?
  - Broadcasting in Laravel allows you to share events between the server-side and client-side applications, enabling real-time features like notifications.
- What is the difference between `hasOne` and `belongsTo` relationships in Laravel?
  - `hasOne` defines a one-to-one relationship where the parent model owns the related model. `belongsTo` defines the inverse relationship where the related model is owned by the parent model.
- What is a policy in Laravel?
  - Policies are classes that organize authorization logic for a specific model.
- How do you optimize a Laravel application?
  - Use caching for routes, views, and queries.
  - Optimize the database with proper indexing.
  - Use eager loading to avoid N+1 query problems.
  - Enable query caching.
- How does Laravel handle error and exception handling?
  - Laravel uses the `App\Exceptions\Handler` class to handle all exceptions. You can log errors, render specific views, or redirect users.
- What is the difference between `@include`, `@yield`, and `@section` in Blade?
  - `@include` includes a partial view.
  - `@yield` defines a placeholder for a section in a layout.
  - `@section` defines content for a section in the layout.
- How can you implement custom helper functions in Laravel?
  - Create a helper file, define functions, and load it via Composer's autoload configuration in `composer.json`.
- What are jobs and workers in Laravel?
  - Jobs represent tasks to be processed, and workers are the processes that execute those tasks.
- What is Laravel Telescope?
  - Telescope is a debugging assistant for Laravel that provides insights into requests, jobs, database queries, and more.
- How can you implement caching in Laravel?
  - You can use caching drivers like file, database, Redis, or Memcached. Example:
    ```php
    Cache::put('key', 'value', $seconds);
    Cache::get('key');
    ```
### General
- What are facades in Laravel? How do they work?
  - Facades provide a static interface to classes in the service container. They act as a proxy to underlying classes and allow calling methods without needing to instantiate the class. Example: `Cache::get('key')`.
- What is the difference between `public`, `protected`, and `private` in a Laravel context?
  - `public`: Methods or properties accessible from anywhere.
  - `protected`: Accessible only within the class and its subclasses.
  - `private`: Accessible only within the class where it's declared.
- What is the use of the `boot` method in Eloquent models?
  - The `boot` method is used to observe or hook into Eloquent model events (e.g., creating, updating, deleting) and to set global scopes.
- What are traits in Laravel?
  - Traits are used to include reusable methods in multiple classes. Example: Using `SoftDeletes` to enable soft deletion functionality in models.
### Authentication and Authorization Questions
- What is the difference between `Auth::attempt()` and `Auth::login()`?
  - `Auth::attempt()` validates user credentials and logs in the user if valid.
  - `Auth::login()` directly logs in a user without validating credentials.
- How does the Laravel Gate work?
  - Gates provide a way to define and authorize user actions at a higher level, like determining if a user can update a post:
    ```php
    Gate::define('update-post', function ($user, $post) {
        return $user->id === $post->user_id;
    });
    ```
- What is Sanctum in Laravel? How is it different from Passport?
  - Sanctum is a lightweight authentication system for API tokens and SPA authentication. Passport is for full OAuth2 authentication.
### Miscellaneous Questions
- What is a Laravel package? How do you create one?
  - Packages extend Laravel's functionality. To create one:
      - Set up a package directory structure.
      - Define service providers.
      - Publish assets or configurations as needed.
- What is the `event:listen` and `event:dispatch` mechanism?
  - `event:listen` registers an event listener, while `event:dispatch` triggers the event. Example:
    ```php
    Event::listen(UserRegistered::class, SendWelcomeEmail::class);
    event(new UserRegistered($user));
    ```
- What is Laravel Horizon?
  - Horizon is a dashboard tool for monitoring and managing Laravel queues powered by Redis.
- Explain the `$fillable` and `$guarded` properties in Laravel models.
  - `$fillable`: Specifies fields allowed for mass assignment.
  - `$guarded`: Specifies fields that are not mass assignable.
- What is the purpose of `broadcastOn()` in Laravel events?
  - It defines the channels the event should be broadcast on.
- What is the difference between `session` and `cache` in Laravel?
  - `session` stores user specific data for the duration of the user's session (e.g. user login info). It typically uses storage like files, database, or cookies
  - `cache` temporarily stores application data to optimise performance. It uses faster storage systems like Redis or Memchached.
- What is the use of the `dd()` function in Laravel?
  - `dd()` stands for "Dump and Die". It is a debugging function used to dump variable contents and stop script execution.
- How does Laravel handle APIs?
  - Laravel provides tools for building RESTful APIs:
    - Use `routes/api.php` for API routes.
    - Return `JSON` responses:
      ```php
      return response()->json(['data' => $data]);
      ```
    - Use `Resource` classes for API responses:
      ```php
      php artisan make:resource UserResource
      ```
    - Example in controller:
      ```php
      return new UserResource(User::find(1));
      ```
- What is Laravel Passport
  - Laravel Passport is a package for API authentication using OAuth2. It provides a full OAuth2 server implementation for your application, allowing you to secure your APIs and manage authentication tokens for users.
- What is CSRF protection in Laravel?
  - CSRF (Cross-Site Request Forgery) protection in Laravel is enabled by default. Laravel uses a CSRF token to verify that the incoming request is from the authenticated user and not from a malicious site. This token is included in each form by using `@csrf` directive in Blade templates.
- What are seeding and factories in Laravel?
  - **Seeder:** Seeder classes are used to populate the database with sample data.
  - **Factory:** Factories are used to generate fake data for models. They can be used to create many records easily.
- What are the key new features in Laravel 11?
  - Laravel 11 introduces several major changes:
    - **Simplified Application Structure:** Removed `Kernel.php` files and unnecessary service providers.
    - **Laravel Reverb:** A built-in WebSocket server for real-time apps.
    - **SQLite by Default:** Used for database, cache, and queue storage.
    - **Health Routing:** A built-in `/up` endpoint for application health checks.
    - **Queue Interaction Testing:** New `withFakeQueueInteractions()` method.
    - **Graceful Encryption Key Rotation:** Allows easy key rotation without data loss.
- How does Laravel 11 differ from Laravel 10?
  - No `Http/Kernel.php` and `Console/Kernel.php` (Middleware and scheduling logic moved to framework).
  - Single `AppServiceProvider.php` instead of multiple providers.
  - Built-in WebSocket server (Reverb).
  - Simpler database defaults (SQLite for sessions, cache, and queues).
  - Performance optimizations like eager loading limits.
- What is health routing in Laravel 11?
  - Laravel 11 introduces a built-in `/up` endpoint that returns a `200 OK` response if the application is running. This helps with uptime monitoring in production environments.
    `GET /up`
    ```json
    {
        "status": "ok"
    }
    ```
---
