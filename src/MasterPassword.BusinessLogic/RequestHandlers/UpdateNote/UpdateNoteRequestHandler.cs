using MasterPassword.DataAccess.MongoDbAtlas;
using MasterPassword.DataAccess.MongoDbAtlas.Entities;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MasterPassword.BusinessLogic.UpdateNote
{
    public interface IUpdateNoteRequestHandler
    {
        Task<UpdateNoteResponse> HandleAsync(UpdateNoteRequest request);
    }

    internal sealed class UpdateNoteRequestHandler(IMongoDbRepository Repository, IEncryptor Encryptor) : IUpdateNoteRequestHandler
    {
        public async Task<UpdateNoteResponse> HandleAsync(UpdateNoteRequest request)
        {
            if (request == null)
                return new UpdateNoteResponse(false) { ErrorMessage = "No data was recevied in the request" };

            if (string.IsNullOrEmpty(request.PrimaryAccountId))
                return new UpdateNoteResponse(false) { ErrorMessage = "Invalid pid" };

            if (string.IsNullOrEmpty(request.SecondaryAccountId))
                return new UpdateNoteResponse(false) { ErrorMessage = "Invalid sid" };

            if (string.IsNullOrWhiteSpace(request.UserKey))
                return new UpdateNoteResponse(false) { ErrorMessage = "Invalid key" };

            var primaryAccountById = await Repository.LoadPrimaryAccountByIdAsync(request.PrimaryAccountId);
            byte[] encryptionKeyBytes = Encoding.UTF8.GetBytes(request.UserKey);

            //var secondaryAccountIds =
            //    primaryAccountById.SecondaryAccounts.Select(x => x.SecondaryAccountId)
            //                                        .Select(x => Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, x))
            //                                        .ToList();

            //if (!secondaryAccountIds.Contains(request.PrimaryAccountId))
            //    return new UpdateNoteResponse(false) { ErrorMessage = "This is not your account. Stop it" };

            var secondaryAccountById = await Repository.LoadSecondaryAccountByIdAsync(request.SecondaryAccountId);
            if(secondaryAccountById.PrimaryAccountId != primaryAccountById._id.ToString())
                return new UpdateNoteResponse(false) { ErrorMessage = "This is not your account. Stop it" };

            //var noteIds =
            //    secondaryAccountById.NoteIds.Select(x => Encryptor.SymmetricKeyDecrypt(encryptionKeyBytes, x))
            //                                        .ToList();

            //if (!noteIds.Contains(request.NoteId))
            //    return new UpdateNoteResponse(false) { ErrorMessage = "This is not your account. Stop it" };

            Note note = await Repository.LoadNoteAsync(request.NoteId);
            if (note is null)
                return new UpdateNoteResponse(false) { ErrorMessage = "Invalid key" };

            if(note.SecondaryAccountId != secondaryAccountById._id.ToString())
                return new UpdateNoteResponse(false) { ErrorMessage = "This is not your account. Stop it" };

            var encryptedTitle = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, request.Title);
            var encryptedDescription = Encryptor.SymmerticKeyEncrypt(encryptionKeyBytes, request.Description);
            note.Title = encryptedTitle;
            note.Description = encryptedDescription;

            await Repository.UpdateNoteAsync(request.NoteId, note);

            return new UpdateNoteResponse(true);
        }
    }
}
