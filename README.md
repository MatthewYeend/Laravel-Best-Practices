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
14. [Direct SQL Queries in Controllers](#direct-sql-queies-in-controllers)
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
28. [Use Constants for Repeated Values](#use-constants-for-repeated-values)
29. [API Rate Limiting](#api-rate-limiting)
30. [Form Input Sanitazation](#form-input-sanitazation)
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
The Good approach follows best practices by using Eloquent ORM instead of raw queries, making the code more readable, maintainable, and reusable. It utilises a query scope (`active()`) for filtering, improving reusability, and `compact()` for cleaner variable passing to the view.

### Bad
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
### Good
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
The Good approach improves readability, maintainability, and security by using Eloquent instead of raw queries. It leverages a Form Request (`UserRequest`) for validation, keeping the controller clean and ensuring data integrity. Using `User::create()` follows Laravel's mass assignment best practices, making the code more concise and easier to manage.
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
The Good approach improves security and readability by properly checking if the user is authenticated before accessing their role. It uses `abort(403)` for cleaner error handling and leverages a role-checking method (`hasRole()`), making the code more reusable and maintainable.
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
The Good approach improves performance and efficiency by using `Cache::remember()`, which avoids unnecessary database queries. It only queries the database if the cache is empty, making the code more optimized, readable, and maintainable.
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
The Good approach follows the event-driven design pattern, improving scalability and maintainability. By dispatching a `UserRegistered` event, it decouples the email-sending logic from the controller, making it easier to manage and extend (e.g., logging, notifications). This keeps the controller clean and adheres to Single Responsibility Principle (SRP).
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
The Good approach improves error logging and debugging by using `Log::error()` instead of `Log::info()`, ensuring proper log severity. It also logs structured data (`error` message and `trace`), making it easier to analyse issues and track errors efficiently.
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
The Good approach improves readability, maintainability, and reusability by using Eloquent instead of raw queries. It leverages a query scope (`pending()`) for filtering, making the code cleaner and reusable across the application.
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
The Good approach improves flexibility and maintainability by using Laravel's notification system instead of directly sending an email. This allows sending password reset notifications via multiple channels (e.g., email, SMS) without modifying the core logic, making the code more scalable and reusable.
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
The Good approach improves consistency and clarity in API responses by explicitly including a `status` field, making it easier for clients to handle responses. This follows best practices for structured API responses, improving readability and maintainability.
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
---
### **Bad**
```php
public function uploadFile()
{
    $path = env('UPLOAD_PATH', 'uploads/default');
    Storage::put($path . '/file.txt', 'content');
}
```
### **Good**
Inside `config/filesystems.php`
```php
upload_path => env('UPLOADED_PATH', 'uploads/default');
```
Inside controller 
```php
public function uploadFile()
{
    $path = config('filesystems.upload_path');
    Storage::put($path . '/file.txt', 'content');
}
```
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
