using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Linq.Expressions;
using System.Security.Claims;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;
// ReSharper disable RedundantExtendsListEntry

namespace AspNet.Identity.MongoDb
{
    /// <summary>
    /// Creates a new instance of a persistence store for roles.
    /// </summary>
    /// <typeparam name="TRole">The type of the class representing a role.</typeparam>
    /// <typeparam name="TKey">The type of the primary key for a role.</typeparam>
    /// <typeparam name="TUserRole">The type of the class representing a user role.</typeparam>
    /// <typeparam name="TRoleClaim">The type of the class representing a role claim.</typeparam>
    public class RoleStore<TRole, TKey, TUserRole, TRoleClaim> :
        IQueryableRoleStore<TRole>,
        IRoleStore<TRole>,
        IDisposable,
        IRoleClaimStore<TRole>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
        where TUserRole : IdentityUserRole<TKey>, new()
        where TRoleClaim : IdentityRoleClaim<TKey>, new()
    {
        #region Constructors

        /// <summary>
        /// Constructs a new instance of <see cref="T:Microsoft.AspNetCore.Identity.EntityFrameworkCore.RoleStore`5" />.
        /// </summary>
        /// <param name="connectionUri">The connection URI used to access the MongoDB.</param>
        /// <param name="roleCollectionName">The user collection name in MongoDB.</param>
        /// <param name="describer">The <see cref="T:Microsoft.AspNetCore.Identity.IdentityErrorDescriber" /> used to describe store errors.</param>
        public RoleStore(string connectionUri, string roleCollectionName = DefaultCollectionName, IdentityErrorDescriber describer = null)
            :base(describer ?? new IdentityErrorDescriber())
        {
            if (string.IsNullOrWhiteSpace(connectionUri)) throw new ArgumentNullException(nameof(connectionUri));
            if (string.IsNullOrWhiteSpace(roleCollectionName)) throw new ArgumentNullException(nameof(roleCollectionName));

            var mongoUrl = new MongoUrl(connectionUri);

            if (string.IsNullOrWhiteSpace(mongoUrl.DatabaseName)) throw new ArgumentNullException("Missing database name in connection string");

            _database = new MongoClient(mongoUrl).GetDatabase(mongoUrl.DatabaseName);
            _collectionName = roleCollectionName;

            this.ErrorDescriber = describer ?? new IdentityErrorDescriber();
        }

        /// <summary>Creates a new instance of the store.</summary>
        /// <param name="databse">The database object.</param>
        /// <param name="roleCollectionName">The role collection name in MongoDB.</param>
        /// <param name="describer">The <see cref="T:Microsoft.AspNetCore.Identity.IdentityErrorDescriber" /> used to describe store errors.</param>
        public RoleStore(IMongoDatabase databse, string roleCollectionName = DefaultCollectionName, IdentityErrorDescriber describer = null)
            : base(describer ?? new IdentityErrorDescriber())
        {
            if (string.IsNullOrWhiteSpace(roleCollectionName)) throw new ArgumentNullException(nameof(roleCollectionName));

            _database = databse ?? throw new ArgumentNullException(nameof(databse));
            _collectionName = roleCollectionName;
        }

        #endregion

        #region Private Members

        /// <summary>
        /// Indicates whether the object is disposed. Used in Disposable pattern.
        /// </summary>
        private bool _disposed;

        /// <summary>
        /// The default collection name.
        /// </summary>
        private const string DefaultCollectionName = "AspNetRoles";

        /// <summary>
        /// The underline MongoDb database
        /// </summary>
        private readonly IMongoDatabase _database;

        /// <summary>
        /// The user collection name.
        /// </summary>
        private readonly string _collectionName;

        #endregion

        /// <summary>
        /// Gets or sets the <see cref="T:Microsoft.AspNetCore.Identity.IdentityErrorDescriber" /> for any error that occurred with the current operation.
        /// </summary>
        public IdentityErrorDescriber ErrorDescriber { get; set; }

        /// <summary>
        /// Gets or sets a flag indicating if changes should be persisted after CreateAsync, UpdateAsync and DeleteAsync are called.
        /// </summary>
        /// <value>
        /// True if changes should be automatically persisted, otherwise false.
        /// </value>
        public bool AutoSaveChanges { get; set; } = true;

        /// <summary>Saves the current store.</summary>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="T:System.Threading.Tasks.Task" /> that represents the asynchronous operation.</returns>
        private async Task SaveChanges(CancellationToken cancellationToken)
        {
            RoleStore<TRole, TContext, TKey, TUserRole, TRoleClaim> roleStore = this;
            if (!roleStore.AutoSaveChanges)
                return;
            int num = await roleStore.Context.SaveChangesAsync(cancellationToken);
        }

        /// <summary>
        /// Creates a new role in a store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role to create in the store.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="T:System.Threading.Tasks.Task`1" /> that represents the <see cref="T:Microsoft.AspNetCore.Identity.IdentityResult" /> of the asynchronous query.</returns>
        public override async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            RoleStore<TRole, TContext, TKey, TUserRole, TRoleClaim> roleStore = this;
            cancellationToken.ThrowIfCancellationRequested();
            roleStore.ThrowIfDisposed();
            if ((object)role == null)
                throw new ArgumentNullException(nameof(role));
            roleStore.Context.Add<TRole>(role);
            await roleStore.SaveChanges(cancellationToken);
            return IdentityResult.Success;
        }

        /// <summary>
        /// Updates a role in a store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role to update in the store.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="T:System.Threading.Tasks.Task`1" /> that represents the <see cref="T:Microsoft.AspNetCore.Identity.IdentityResult" /> of the asynchronous query.</returns>
        public override async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            RoleStore<TRole, TContext, TKey, TUserRole, TRoleClaim> roleStore = this;
            cancellationToken.ThrowIfCancellationRequested();
            roleStore.ThrowIfDisposed();
            if ((object)role == null)
                throw new ArgumentNullException(nameof(role));
            roleStore.Context.Attach<TRole>(role);
            role.ConcurrencyStamp = Guid.NewGuid().ToString();
            roleStore.Context.Update<TRole>(role);
            try
            {
                await roleStore.SaveChanges(cancellationToken);
            }
            catch (DbUpdateConcurrencyException ex)
            {
                return IdentityResult.Failed(roleStore.ErrorDescriber.ConcurrencyFailure());
            }
            return IdentityResult.Success;
        }

        /// <summary>
        /// Deletes a role from the store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role to delete from the store.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="T:System.Threading.Tasks.Task`1" /> that represents the <see cref="T:Microsoft.AspNetCore.Identity.IdentityResult" /> of the asynchronous query.</returns>
        public override async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            RoleStore<TRole, TContext, TKey, TUserRole, TRoleClaim> roleStore = this;
            cancellationToken.ThrowIfCancellationRequested();
            roleStore.ThrowIfDisposed();
            if ((object)role == null)
                throw new ArgumentNullException(nameof(role));
            roleStore.Context.Remove<TRole>(role);
            try
            {
                await roleStore.SaveChanges(cancellationToken);
            }
            catch (DbUpdateConcurrencyException ex)
            {
                return IdentityResult.Failed(roleStore.ErrorDescriber.ConcurrencyFailure());
            }
            return IdentityResult.Success;
        }

        /// <summary>
        /// Gets the ID for a role from the store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose ID should be returned.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="T:System.Threading.Tasks.Task`1" /> that contains the ID of the role.</returns>
        public virtual Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if ((object)role == null)
                throw new ArgumentNullException(nameof(role));
            return Task.FromResult<string>(this.ConvertIdToString(role.Id));
        }

        /// <summary>
        /// Gets the name of a role from the store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose name should be returned.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="T:System.Threading.Tasks.Task`1" /> that contains the name of the role.</returns>
        public virtual Task<string> GetRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if ((object)role == null)
                throw new ArgumentNullException(nameof(role));
            return Task.FromResult<string>(role.Name);
        }

        /// <summary>
        /// Sets the name of a role in the store as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose name should be set.</param>
        /// <param name="roleName">The name of the role.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="T:System.Threading.Tasks.Task" /> that represents the asynchronous operation.</returns>
        public virtual Task SetRoleNameAsync(TRole role, string roleName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if ((object)role == null)
                throw new ArgumentNullException(nameof(role));
            role.Name = roleName;
            return Task.CompletedTask;
        }

        /// <summary>
        /// Converts the provided <paramref name="id" /> to a strongly typed key object.
        /// </summary>
        /// <param name="id">The id to convert.</param>
        /// <returns>An instance of <typeparamref name="TKey" /> representing the provided <paramref name="id" />.</returns>
        public virtual TKey ConvertIdFromString(string id)
        {
            if (id == null)
                return default(TKey);
            return (TKey)TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(id);
        }

        /// <summary>
        /// Converts the provided <paramref name="id" /> to its string representation.
        /// </summary>
        /// <param name="id">The id to convert.</param>
        /// <returns>An <see cref="T:System.String" /> representation of the provided <paramref name="id" />.</returns>
        public virtual string ConvertIdToString(TKey id)
        {
            if (id.Equals(default(TKey)))
                return (string)null;
            return id.ToString();
        }

        /// <summary>
        /// Finds the role who has the specified ID as an asynchronous operation.
        /// </summary>
        /// <param name="id">The role ID to look for.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="T:System.Threading.Tasks.Task`1" /> that result of the look up.</returns>
        public override Task<TRole> FindByIdAsync(string id, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            TKey roleId = this.ConvertIdFromString(id);
            return this.Roles.FirstOrDefaultAsync<TRole>((Expression<Func<TRole, bool>>)(u => u.Id.Equals(roleId)), cancellationToken);
        }

        /// <summary>
        /// Finds the role who has the specified normalized name as an asynchronous operation.
        /// </summary>
        /// <param name="normalizedName">The normalized role name to look for.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="T:System.Threading.Tasks.Task`1" /> that result of the look up.</returns>
        public override Task<TRole> FindByNameAsync(string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            return this.Roles.FirstOrDefaultAsync<TRole>((Expression<Func<TRole, bool>>)(r => r.NormalizedName == normalizedName), cancellationToken);
        }

        /// <summary>
        /// Get a role's normalized name as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose normalized name should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="T:System.Threading.Tasks.Task`1" /> that contains the name of the role.</returns>
        public virtual Task<string> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if ((object)role == null)
                throw new ArgumentNullException(nameof(role));
            return Task.FromResult<string>(role.NormalizedName);
        }

        /// <summary>
        /// Set a role's normalized name as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose normalized name should be set.</param>
        /// <param name="normalizedName">The normalized name to set</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="T:System.Threading.Tasks.Task" /> that represents the asynchronous operation.</returns>
        public virtual Task SetNormalizedRoleNameAsync(TRole role, string normalizedName, CancellationToken cancellationToken = default(CancellationToken))
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();
            if ((object)role == null)
                throw new ArgumentNullException(nameof(role));
            role.NormalizedName = normalizedName;
            return Task.CompletedTask;
        }

        /// <summary>Throws if this class has been disposed.</summary>
        protected void ThrowIfDisposed()
        {
            if (this._disposed)
                throw new ObjectDisposedException(this.GetType().Name);
        }

        /// <summary>Dispose the stores</summary>
        public void Dispose()
        {
            this._disposed = true;
        }

        /// <summary>
        /// Get the claims associated with the specified <paramref name="role" /> as an asynchronous operation.
        /// </summary>
        /// <param name="role">The role whose claims should be retrieved.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>A <see cref="T:System.Threading.Tasks.Task`1" /> that contains the claims granted to a role.</returns>
        public override async Task<IList<Claim>> GetClaimsAsync(TRole role, CancellationToken cancellationToken = default(CancellationToken))
        {
            RoleStore<TRole, TContext, TKey, TUserRole, TRoleClaim> roleStore = this;
            roleStore.ThrowIfDisposed();
            if ((object)role == null)
                throw new ArgumentNullException(nameof(role));
            return (IList<Claim>)await roleStore.RoleClaims.Where<TRoleClaim>((Expression<Func<TRoleClaim, bool>>)(rc => rc.RoleId.Equals(role.Id))).Select<TRoleClaim, Claim>((Expression<Func<TRoleClaim, Claim>>)(c => new Claim(c.ClaimType, c.ClaimValue))).ToListAsync<Claim>(cancellationToken);
        }

        /// <summary>
        /// Adds the <paramref name="claim" /> given to the specified <paramref name="role" />.
        /// </summary>
        /// <param name="role">The role to add the claim to.</param>
        /// <param name="claim">The claim to add to the role.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="T:System.Threading.Tasks.Task" /> that represents the asynchronous operation.</returns>
        public override Task AddClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            this.ThrowIfDisposed();
            if ((object)role == null)
                throw new ArgumentNullException(nameof(role));
            if (claim == null)
                throw new ArgumentNullException(nameof(claim));
            this.RoleClaims.Add(this.CreateRoleClaim(role, claim));
            return (Task)Task.FromResult<bool>(false);
        }

        /// <summary>
        /// Removes the <paramref name="claim" /> given from the specified <paramref name="role" />.
        /// </summary>
        /// <param name="role">The role to remove the claim from.</param>
        /// <param name="claim">The claim to remove from the role.</param>
        /// <param name="cancellationToken">The <see cref="T:System.Threading.CancellationToken" /> used to propagate notifications that the operation should be canceled.</param>
        /// <returns>The <see cref="T:System.Threading.Tasks.Task" /> that represents the asynchronous operation.</returns>
        public override async Task RemoveClaimAsync(TRole role, Claim claim, CancellationToken cancellationToken = default(CancellationToken))
        {
            RoleStore<TRole, TContext, TKey, TUserRole, TRoleClaim> roleStore = this;
            roleStore.ThrowIfDisposed();
            if ((object)role == null)
                throw new ArgumentNullException(nameof(role));
            if (claim == null)
                throw new ArgumentNullException(nameof(claim));
            DbSet<TRoleClaim> roleClaims = roleStore.RoleClaims;
            Expression<Func<TRoleClaim, bool>> predicate = (Expression<Func<TRoleClaim, bool>>)(rc => rc.RoleId.Equals(role.Id) && rc.ClaimValue == claim.Value && rc.ClaimType == claim.Type);
            foreach (TRoleClaim entity in await roleClaims.Where<TRoleClaim>(predicate).ToListAsync<TRoleClaim>(cancellationToken))
                roleStore.RoleClaims.Remove(entity);
        }

        /// <summary>
        /// A navigation property for the roles the store contains.
        /// </summary>
        public override IQueryable<TRole> Roles
        {
            get
            {
                return (IQueryable<TRole>)this.Context.Set<TRole>();
            }
        }

        private DbSet<TRoleClaim> RoleClaims
        {
            get
            {
                return this.Context.Set<TRoleClaim>();
            }
        }

        /// <summary>Creates a entity representing a role claim.</summary>
        /// <param name="role">The associated role.</param>
        /// <param name="claim">The associated claim.</param>
        /// <returns>The role claim entity.</returns>
        protected virtual TRoleClaim CreateRoleClaim(TRole role, Claim claim)
        {
            TRoleClaim instance = Activator.CreateInstance<TRoleClaim>();
            instance.RoleId = role.Id;
            instance.ClaimType = claim.Type;
            instance.ClaimValue = claim.Value;
            return instance;
        }
    }
}
