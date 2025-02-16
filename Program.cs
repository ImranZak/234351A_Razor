using _234351A_Razor.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;
using _234351A_Razor.Models;
using Microsoft.AspNetCore.Mvc;

var builder = WebApplication.CreateBuilder(args);

// Load configurations
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

// Register Identity Services
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = true;
    options.Password.RequiredLength = 12;
    options.Password.RequireDigit = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = true;
    options.Password.RequiredUniqueChars = 2;
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(30);
})
.AddRoles<IdentityRole>()
.AddEntityFrameworkStores<AuthDbContext>()
.AddDefaultTokenProviders();

// Ensure Identity Services Are Registered
builder.Services.AddScoped<UserManager<ApplicationUser>>();
builder.Services.AddScoped<RoleManager<IdentityRole>>();
builder.Services.AddScoped<SignInManager<ApplicationUser>>();

// Secure session settings
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(20);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

// Enable Data Protection for encrypting sensitive data
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(@"/keys"))
    .SetApplicationName("BookwormsOnline");

// Configure secure session management
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Login";
    options.AccessDeniedPath = "/AccessDenied";
    options.ReturnUrlParameter = "returnUrl";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
    options.SlidingExpiration = true;
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});

//  Fix: Extend 2FA Token Expiry to 5 Minutes
builder.Services.Configure<DataProtectionTokenProviderOptions>(options =>
{
    options.TokenLifespan = TimeSpan.FromMinutes(5);
});

//  Fix: Ensure "Email" is Used as 2FA Provider
builder.Services.Configure<IdentityOptions>(options =>
{
    options.Tokens.ProviderMap["Email"] = new TokenProviderDescriptor(typeof(DataProtectorTokenProvider<ApplicationUser>));
});

// Add Razor Pages
builder.Services.AddRazorPages();
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

var app = builder.Build();

// Apply database migrations & seed roles properly
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();
    var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();

    SeedRolesAndAdmin(roleManager, userManager).GetAwaiter().GetResult();
}

static async Task SeedRolesAndAdmin(RoleManager<IdentityRole> roleManager, UserManager<ApplicationUser> userManager)
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
// Handle specific status codes dynamically (403, 404, etc.)
app.UseStatusCodePagesWithReExecute("/Error/{0}");

if (!app.Environment.IsDevelopment())
{
    // Handle unhandled server-side errors (500, etc.)
    app.UseExceptionHandler("/Error/500");
    app.UseHsts();
}

// Configure HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error");

    // Hardened Security Headers (CSP & others)
    app.Use(async (context, next) =>
    {
        context.Response.Headers.Append("Content-Security-Policy",
            "frame-ancestors 'self' https://www.google.com; " +
            "script-src 'self' https://www.google.com https://www.gstatic.com 'unsafe-inline'; " +
            "frame-src 'self' https://www.google.com https://www.recaptcha.net;");

        context.Response.Headers.Append("X-Frame-Options", "DENY");
        context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
        context.Response.Headers.Append("Referrer-Policy", "no-referrer");

        await next();
    });

    app.UseHsts();
}

// Handle status codes like 404 (Not Found) and 403 (Access Denied)
app.UseStatusCodePagesWithReExecute("/Error", "?statusCode={0}");

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Ensure `UseSession()` is placed BEFORE `UseAuthentication()`
app.UseSession();
app.UseAuthentication();

// Secure Session Management (Prevents Session Hijacking)
app.Use(async (context, next) =>
{
    var userManager = context.RequestServices.GetRequiredService<UserManager<ApplicationUser>>();
    var signInManager = context.RequestServices.GetRequiredService<SignInManager<ApplicationUser>>();

    // Skip session validation for email confirmation
    if (context.Request.Path.StartsWithSegments("/ConfirmEmail"))
    {
        await next();
        return;
    }

    if (!context.User.Identity.IsAuthenticated)
    {
        await next();
        return; // Skip session validation if user is not logged in
    }

    var user = await userManager.GetUserAsync(context.User);
    if (user != null)
    {
        string storedSecurityStamp = await userManager.GetSecurityStampAsync(user);
        string? sessionToken = context.Session.GetString("AuthToken");

        if (sessionToken == null || storedSecurityStamp != sessionToken)
        {
            // Prevent infinite logout loop
            if (!context.Request.Path.StartsWithSegments("/Login"))
            {
                await signInManager.SignOutAsync();
                context.Session.Clear();
                context.Response.Redirect("/Login?Message=SessionExpired");
                return;
            }
        }
    }

    await next();
});

app.UseAuthorization();
app.MapRazorPages();
app.Run();
