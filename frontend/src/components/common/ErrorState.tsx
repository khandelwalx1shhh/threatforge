import styles from './ErrorState.module.css';

interface ErrorStateProps {
  message: string;
  onRetry?: () => void;
  title?: string;
}

export function ErrorState({ message, onRetry, title = 'Analysis Failed' }: ErrorStateProps) {
  return (
    <div className={styles.errorContainer} role="alert" aria-live="assertive">
      <div className={styles.errorHeader}>
        <span className={styles.errorIcon}>⚠</span>
        <h3 className={styles.errorTitle}>{title}</h3>
      </div>
      <p className={styles.errorMessage}>{message}</p>
      
      {onRetry && (
        <button 
          className={styles.retryBtn} 
          onClick={onRetry}
          aria-label="Retry the failed request"
        >
          Try Again
        </button>
      )}
    </div>
  );
}
