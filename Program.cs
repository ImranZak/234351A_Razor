using _234351A_Razor.Data;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.DataProtection;
using _234351A_Razor.Models;

var builder = WebApplication.CreateBuilder(args);

// Retrieve the correct connection string
var connectionString = builder.Configuration.GetConnectionString("AuthConnectionString");
if (string.IsNullOrEmpty(connectionString))
{
    throw new ArgumentNullException("Database connection string is missing. Check appsettings.json.");
}

// Configure Database Context
builder.Services.AddDbContext<AuthDbContext>(options =>
    options.UseSqlServer(connectionString));

// Configure Identity with custom ApplicationUser model
builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
    .AddEntityFrameworkStores<AuthDbContext>()
    .AddDefaultTokenProviders();

// Enable Data Protection for encrypting sensitive data
builder.Services.AddDataProtection()
    .PersistKeysToFileSystem(new DirectoryInfo(@"./keys"))
    .SetApplicationName("BookwormsOnline");

// Configure authentication to require email confirmation
builder.Services.Configure<IdentityOptions>(options =>
{
    options.SignIn.RequireConfirmedAccount = true;
});

builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath = "/Login";
    options.AccessDeniedPath = "/AccessDenied";
    options.ExpireTimeSpan = TimeSpan.FromMinutes(20);
    options.SlidingExpiration = true;
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
});



// Add Razor Pages and Exception Filter
builder.Services.AddRazorPages();
builder.Services.AddDatabaseDeveloperPageExceptionFilter();

var app = builder.Build();

// Configure HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}
// Handle status codes like 404 (Not Found) and 403 (Access Denied) by redirecting to custom error pages
app.UseStatusCodePagesWithRedirects("/Error/{0}");

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.Run();
