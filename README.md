# Laravel-Best-Practises

## Controller code
### Bad
```
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
#### Problems
- Direct database queries in controllers are not clean and violate the separation of concerns.
- Missing validation for incoming data.
- No use of Eloquent, which is one of Laravel's core strengths.
### Good
```
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
#### Improvements
- Using Eloquent ORM for cleaner, more readable queries.
- Data validation is handled by a custom `UserRequest` form request, improving code separation and reusability.

## Database Querying
### Bad
```
// Direct query execution without optimization
$users = DB::table('users')
    ->join('orders', 'users.id', '=', 'orders.user_id')
    ->where('orders.created_at', '>', now()->subMonth())
    ->select('users.name', 'orders.total')
    ->get();
```
#### Problems
- Direct query construction in controllers or views can lead to maintenance issues.
- No use of eager loading for relationships, potentially causing the N+1 problem.
### Good
```
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
#### Improvements
- Utilised eager loading (`with()`) to prevent the N+1 query problem.
- Encapsulated business logic within the model or controller, following the single responsibility principle.

## Validation
### Bad
```
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
#### Problems
- Missing validation logic.
- Direct manipulation of the request data without filtering or validating inputs.
### Good
```
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
Controller
```
public function store(UserRequest $request)
{
    $user = User::create($request->validated());
}
```
#### Improvements
- Custom form request `UserRequest` handles validation.
- The `validated()` method ensures only validated data is passed to the model.

## Security Concerns
### Bad 
```
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
#### Problems
- While the logic is mostly correct, it does not utilize Laravel's built-in `attempt()` method, which can handle additional features such as rate-limiting and locking.

### Good
```
public function login(Request $request)
{
    $credentials = $request->only('email', 'password');

    if (Auth::attempt($credentials)) {
        return redirect()->route('dashboard');
    }

    return back()->withErrors(['email' => 'Invalid credentials']);
}
```
#### Improvements
- Using `Auth::attempt()` method for authentication, which provides additional security features.
- `attempt()` automatically hashes the password and checks for other security measures.

## Error Handling
### Bad
```
public function show($id)
{
    $user = User::find($id);

    if (!$user) {
        return response('User not found', 404);
    }

    return view('users.show', compact('user'));
}
```
#### Problems
- Returns a raw response instead of using Laravel’s built-in exception handling.
- Repeating error message logic in multiple places.
### Good
```
public function show($id)
{
    $user = User::findOrFail($id);

    return view('users.show', compact('user'));
}
```
#### Improvements
- Use `findOrFail()`, which automatically throws a `ModelNotFoundException` if the user is not found.
- Laravel will catch the exception and render a 404 page automatically, providing consistent error handling.

## File Uploads
### Bad
```
public function upload(Request $request)
{
    $request->file('image')->move('uploads', 'image.jpg');
}
```
#### Problems
- Hardcoding file paths and names.
- Lack of validation for file types, sizes, etc.
### Good
```
public function upload(Request $request)
{
    $request->validate([
        'image' => 'required|image|mimes:jpeg,png,jpg,gif|max:2048',
    ]);

    $path = $request->file('image')->store('uploads', 'public');

    return response()->json(['path' => $path]);
}
```
#### Improvements
- Validate file type and size before uploading.
- Store files using Laravel's built-in storage system for better handling of file paths.
