using _234351A_Razor.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;
using _234351A_Razor.Models;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

// allows appsettings.Development.json to be loaded in Development mode
builder.Configuration
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
    .AddJsonFile($"appsettings.{builder.Environment.EnvironmentName}.json", optional: true, reloadOnChange: true)
    .AddEnvironmentVariables();


// Ensure database connection string is set
var connectionString = builder.Configuration.GetConnectionString("AuthConnectionString");
if (string.IsNullOrEmpty(connectionString))
{
    throw new ArgumentNullException("Database connection string is missing. Check appsettings.json.");
}

// Configure Database Context
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlServer(connectionString));

//  Register Identity Services Properly
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = true;
    options.Password.RequiredLength = 12;
    options.Password.RequireDigit = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredUniqueChars = 2;
    options.Password.RequiredLength = 12;
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30); // Minimum time before password change
})
.AddRoles<IdentityRole>()
.AddEntityFrameworkStores<AuthDbContext>()
.AddDefaultTokenProviders();



//  Ensure Identity Services Are Registered
builder.Services.AddScoped<UserManager<ApplicationUser>>();
builder.Services.AddScoped<RoleManager<IdentityRole>>();
builder.Services.AddScoped<SignInManager<ApplicationUser>>();

// Secure session settings
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20); // Auto logout after 20 minutes of inactivity
    options.Cookie.HttpOnly = true; // Prevent JavaScript access to session
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Always send session cookie over HTTPS
    options.Cookie.SameSite = SameSiteMode.Strict; // Prevent CSRF attacks
});

//  Enable Data Protection for encrypting sensitive data
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(@"/keys"))
    .SetApplicationName("BookwormsOnline");

//  Configure secure session management
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Login";
    options.AccessDeniedPath = "/AccessDenied";
    options.ReturnUrlParameter = "returnUrl";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
    options.SlidingExpiration = true;
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
});

//  Add Razor Pages
builder.Services.AddRazorPages(options =>
{});
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

var app = builder.Build();

// Apply database migrations & seed roles properly (NO `await` inside `Main()`)
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();

    await SeedRolesAndAdmin(roleManager, userManager);
}

async Task SeedRolesAndAdmin(RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager)
{
    string[] roleNames = { "Admin", "Member" };
    foreach (var roleName in roleNames)
    {
        if (!await roleManager.RoleExistsAsync(roleName))
        {
            await roleManager.CreateAsync(new IdentityRole(roleName));
        }
    }
}

//  Configure HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error");

    //  FIX: Allow reCAPTCHA through Content Security Policy (CSP)
    app.Use(async (context, next) =>
    {
        context.Response.Headers.Append("Content-Security-Policy",
            "frame-ancestors 'self' https://www.google.com; " +
            "script-src 'self' https://www.google.com https://www.gstatic.com; " +
            "frame-src 'self' https://www.google.com https://www.recaptcha.net;");
        await next();
    });


    app.UseHsts();
}

// Handle status codes like 404 (Not Found) and 403 (Access Denied)
app.UseStatusCodePagesWithReExecute("/Error", "?statusCode={0}");

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

//  FIX: Ensure `UseSession()` is placed BEFORE `UseAuthentication()`
app.UseSession();
app.UseAuthentication();
app.Use(async (context, next) =>
{
    var userManager = context.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
    var signInManager = context.RequestServices.GetRequiredService<SignInManager<ApplicationUser>>();

    // Skip session validation for email confirmation requests
    if (context.Request.Path.StartsWithSegments("/ConfirmEmail"))
    {
        await next();
        return;
    }

    var user = await userManager.GetUserAsync(context.User);
    if (user != null)
    {
        string storedSecurityStamp = await userManager.GetSecurityStampAsync(user);
        string? sessionToken = context.Session.GetString("AuthToken");

        if (sessionToken == null || storedSecurityStamp != sessionToken)
        {
            // Invalidate session and force logout
            await signInManager.SignOutAsync();
            context.Session.Clear();
            context.Response.Redirect("/Login?Message=SessionExpired");
            return;
        }
    }

    await next();
});
app.UseAuthorization();

app.MapRazorPages();
app.Run();
