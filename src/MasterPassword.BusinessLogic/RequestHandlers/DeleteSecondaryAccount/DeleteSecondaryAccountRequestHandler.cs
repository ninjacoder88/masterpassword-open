using MasterPassword.DataAccess.MongoDbAtlas;
using MasterPassword.DataAccess.MongoDbAtlas.Entities;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MasterPassword.BusinessLogic.DeleteSecondaryAccount
{
    public interface IDeleteSecondaryAccountRequestHandler
    {
        Task<DeleteSecondaryAccountResponse> HandleAsync(DeleteSecondaryAccountRequest request);
    }

    internal sealed class DeleteSecondaryAccountRequestHandler(IMongoDbRepository Repository, IEncryptor Encryptor) 
        : IDeleteSecondaryAccountRequestHandler
    {
        public async Task<DeleteSecondaryAccountResponse> HandleAsync(DeleteSecondaryAccountRequest request)
        {
            if (request is null)
                return new DeleteSecondaryAccountResponse(false) { ErrorMessage = "No data was recevied in the request" };

            if (string.IsNullOrEmpty(request.PrimaryAccountId))
                return new DeleteSecondaryAccountResponse(false) { ErrorMessage = "Invalid pid" };

            if (string.IsNullOrEmpty(request.SecondaryAccountId))
                return new DeleteSecondaryAccountResponse(false) { ErrorMessage = "Invalid sid" };

            if (string.IsNullOrWhiteSpace(request.UserKey))
                return new DeleteSecondaryAccountResponse(false) { ErrorMessage = "Invalid key" };

            byte[] encryptionKeyBytes = Encoding.UTF8.GetBytes(request.UserKey);

            //load primary account
            var primaryAccount = await Repository.LoadPrimaryAccountByIdAsync(request.PrimaryAccountId);

            //var secondaryAccountObjects = primaryAccount.SecondaryAccounts.Select(x => new
            //{
            //    DecryptedId = Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, x.SecondaryAccountId),
            //    Shallow = x
            //}).ToList();

            //var secondaryAccountShallow = secondaryAccountObjects.FirstOrDefault(x => x.DecryptedId == request.SecondaryAccountId);

            //validate secondary account is owned by primary account
            //if(secondaryAccountShallow is null)
            //    return new DeleteSecondaryAccountResponse(false) { ErrorMessage = "This is not your account. Stop it" };

            //load secondary account
            var secondaryAccount = await Repository.LoadSecondaryAccountByIdAsync(request.SecondaryAccountId);

            if(secondaryAccount.PrimaryAccountId != primaryAccount._id.ToString())
                return new DeleteSecondaryAccountResponse(false) { ErrorMessage = "This is not your account. Stop it" };

            //var noteIds = secondaryAccount.NoteIds.Select(x => Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, x)).ToList();
            List<Note> notes = await Repository.LoadNotesForSecondaryAccountAsync(secondaryAccount._id.ToString());

            //remove notes associated with secondary account
            foreach(var noteId in notes.Select(x => x._id.ToString()))
                await Repository.DeleteNoteAsync(noteId);

            //await Repository.RemovePrimaryAccountShallowReferencesAsync(request.PrimaryAccountId, secondaryAccountShallow.Shallow);

            await Repository.DeleteSecondaryAccountAsync(request.SecondaryAccountId);

            return new DeleteSecondaryAccountResponse(true);
        }
    }
}
